"""Explicit, versioned SQLite migrations for the local-first application.

The ownership migration rebuilds two tables to add required foreign keys. It is
only run by the CLI after a verified backup and an explicit legacy owner are
provided; application startup never changes the database schema.
"""

import hashlib
import json
import sqlite3
from pathlib import Path

from sqlalchemy import inspect, text

from app.database.db import db
from app.database.models import AdminAuditLog, ActivityLog, Investigation, LoginThrottle, User


CURRENT_SCHEMA_VERSION = 2
_LEGACY_INVESTIGATION_COLUMNS = {
    "id", "target", "query_type", "risk_score", "verdict", "created_at",
    "analysis_status", "summary", "evidence_json", "recommendations_json",
    "enrichment_json", "data_sources_json",
}
_LEGACY_ACTIVITY_COLUMNS = {
    "id", "event_type", "message", "investigation_id", "created_at",
}


def _require_sqlite():
    if db.engine.dialect.name != "sqlite":
        raise RuntimeError("The versioned ownership migration currently supports SQLite only.")


def _ensure_foundation():
    """Create account and migration metadata tables without touching old data."""
    _require_sqlite()
    with db.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, name VARCHAR(100) NOT NULL, "
            "applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, details_json TEXT)"
        )
        User.__table__.create(connection, checkfirst=True)
        LoginThrottle.__table__.create(connection, checkfirst=True)
        AdminAuditLog.__table__.create(connection, checkfirst=True)
        applied = connection.execute(
            text("SELECT 1 FROM schema_migrations WHERE version = 1")
        ).first()
        if not applied:
            connection.execute(
                text("INSERT INTO schema_migrations (version, name, details_json) VALUES (1, 'user-foundation', '{}')")
            )


def schema_version():
    """Return the current schema version, or zero when initialization is required."""
    try:
        if "schema_migrations" not in inspect(db.engine).get_table_names():
            return 0
        with db.engine.connect() as connection:
            return int(connection.execute(text("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")).scalar_one())
    except Exception:
        return 0


def _table_columns(connection, table_name):
    statement = f'PRAGMA table_info("{table_name}")'
    if hasattr(connection, "exec_driver_sql"):
        rows = connection.exec_driver_sql(statement).fetchall()
    else:
        rows = connection.execute(statement).fetchall()
    return {row[1] for row in rows}


def _validate_legacy_schema(connection, table_names):
    def query(statement):
        result = connection.exec_driver_sql(statement) if hasattr(connection, "exec_driver_sql") else connection.execute(statement)
        return result.fetchall()

    if "investigations" in table_names:
        columns = _table_columns(connection, "investigations")
        if columns != _LEGACY_INVESTIGATION_COLUMNS:
            raise RuntimeError("The investigations schema differs from the expected legacy schema; migration stopped safely.")
        indexes = query(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='investigations' AND sql IS NOT NULL"
        )
        triggers = query(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='investigations'"
        )
        if indexes or triggers:
            raise RuntimeError("Custom indexes or triggers exist on investigations; migration stopped to preserve them.")
    if "activity_logs" in table_names:
        columns = _table_columns(connection, "activity_logs")
        if columns != _LEGACY_ACTIVITY_COLUMNS:
            raise RuntimeError("The activity_logs schema differs from the expected legacy schema; migration stopped safely.")
        indexes = query(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='activity_logs' AND sql IS NOT NULL"
        )
        triggers = query(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='activity_logs'"
        )
        if indexes or triggers:
            raise RuntimeError("Custom indexes or triggers exist on activity_logs; migration stopped to preserve them.")


def _legacy_owner_id(username):
    if not username:
        return None
    normalized = username.strip().lower()
    with db.engine.connect() as connection:
        row = connection.execute(
            text("SELECT id, role, is_active, is_legacy_owner FROM users WHERE username = :username"),
            {"username": normalized},
        ).first()
    if not row or row.role != "user" or not row.is_active or not row.is_legacy_owner:
        raise RuntimeError("The named legacy owner must be an existing active standard user.")
    return int(row.id)


def _rebuild_ownership_tables(legacy_owner_id, details):
    raw = db.engine.raw_connection()
    cursor = raw.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute("BEGIN IMMEDIATE")
        table_names = {row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        _validate_legacy_schema(cursor, table_names)

        investigations_exist = "investigations" in table_names
        activity_exists = "activity_logs" in table_names
        investigation_count = (
            cursor.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
            if investigations_exist else 0
        )
        activity_count = (
            cursor.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
            if activity_exists else 0
        )
        if (investigation_count or activity_count) and legacy_owner_id is None:
            raise RuntimeError("Existing records require an explicitly provisioned standard legacy-owner account.")

        orphan_count = 0
        if investigations_exist and activity_exists:
            orphan_count = cursor.execute(
                "SELECT COUNT(*) FROM activity_logs a LEFT JOIN investigations i "
                "ON a.investigation_id = i.id WHERE a.investigation_id IS NOT NULL AND i.id IS NULL"
            ).fetchone()[0]
        if orphan_count:
            raise RuntimeError("Existing activity records reference missing investigations; migration stopped safely.")

        cursor.execute(
            "CREATE TABLE investigations_new ("
            "id INTEGER NOT NULL PRIMARY KEY, target VARCHAR(2048) NOT NULL, "
            "query_type VARCHAR(50) NOT NULL, risk_score INTEGER, verdict VARCHAR(50), "
            "analysis_status VARCHAR(32) NOT NULL DEFAULT 'legacy', summary TEXT, "
            "evidence_json TEXT, recommendations_json TEXT, enrichment_json TEXT, "
            "data_sources_json TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
            "owner_user_id INTEGER NOT NULL, "
            "FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE RESTRICT, "
            "UNIQUE(id, owner_user_id))"
        )
        if investigations_exist:
            cursor.execute(
                "INSERT INTO investigations_new (id, target, query_type, risk_score, verdict, "
                "analysis_status, summary, evidence_json, recommendations_json, enrichment_json, "
                "data_sources_json, created_at, owner_user_id) "
                "SELECT id, target, query_type, risk_score, verdict, analysis_status, summary, "
                "evidence_json, recommendations_json, enrichment_json, data_sources_json, created_at, ? "
                "FROM investigations",
                (legacy_owner_id,),
            )

        cursor.execute(
            "CREATE TABLE activity_logs_new ("
            "id INTEGER NOT NULL PRIMARY KEY, event_type VARCHAR(50) NOT NULL, "
            "message VARCHAR(255) NOT NULL, user_id INTEGER NOT NULL, investigation_id INTEGER, "
            "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT, "
            "FOREIGN KEY(investigation_id, user_id) REFERENCES investigations(id, owner_user_id) ON DELETE RESTRICT)"
        )
        if activity_exists:
            cursor.execute(
                "INSERT INTO activity_logs_new (id, event_type, message, user_id, investigation_id, created_at) "
                "SELECT id, event_type, message, ?, investigation_id, created_at FROM activity_logs",
                (legacy_owner_id,),
            )

        if activity_exists:
            cursor.execute("DROP TABLE activity_logs")
        if investigations_exist:
            cursor.execute("DROP TABLE investigations")
        cursor.execute("ALTER TABLE investigations_new RENAME TO investigations")
        cursor.execute("ALTER TABLE activity_logs_new RENAME TO activity_logs")
        cursor.execute("CREATE INDEX ix_investigations_owner_created ON investigations(owner_user_id, created_at)")
        cursor.execute("CREATE INDEX ix_activity_logs_user_created ON activity_logs(user_id, created_at)")
        details.update({"legacy_owner_user_id": legacy_owner_id, "investigations": investigation_count, "activity_logs": activity_count})
        cursor.execute(
            "INSERT INTO schema_migrations (version, name, details_json) VALUES (2, 'per-user-ownership', ?)",
            (json.dumps(details, sort_keys=True),),
        )
        violations = cursor.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError("SQLite reported a foreign-key violation after migration.")
        raw.commit()
        cursor.execute("PRAGMA foreign_keys=ON")
    except Exception:
        raw.rollback()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error:
            pass
        raise
    finally:
        cursor.close()
        raw.close()
    return details


def upgrade_database(legacy_owner_username=None):
    """Apply pending schema migrations; existing records require an explicit owner."""
    _ensure_foundation()
    version = schema_version()
    if version >= CURRENT_SCHEMA_VERSION:
        return {"version": version, "already_current": True}

    _require_sqlite()
    table_names = set(inspect(db.engine).get_table_names())
    if "investigations" not in table_names:
        db.create_all()
        details = {"legacy_owner_user_id": None, "investigations": 0, "activity_logs": 0}
        with db.engine.begin() as connection:
            connection.execute(
                text("INSERT INTO schema_migrations (version, name, details_json) VALUES (2, 'per-user-ownership', :details)"),
                {"details": json.dumps(details, sort_keys=True)},
            )
        return {"version": CURRENT_SCHEMA_VERSION, **details}

    connection = db.engine.raw_connection()
    try:
        cursor = connection.cursor()
        _validate_legacy_schema(cursor, table_names)
        existing = cursor.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        activity = cursor.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0] if "activity_logs" in table_names else 0
    finally:
        connection.close()

    owner_id = _legacy_owner_id(legacy_owner_username) if legacy_owner_username else None
    if (existing or activity) and owner_id is None:
        raise RuntimeError(
            "This database contains legacy records. Provision a standard legacy-owner account and rerun with --legacy-owner."
        )
    details = _rebuild_ownership_tables(
        owner_id,
        {"legacy_owner_username": legacy_owner_username.strip().lower() if legacy_owner_username else None},
    )
    return {"version": CURRENT_SCHEMA_VERSION, **details}


def _database_path():
    _require_sqlite()
    with db.engine.connect() as connection:
        rows = connection.exec_driver_sql("PRAGMA database_list").fetchall()
    main = next((row[2] for row in rows if row[1] == "main"), "")
    if not main:
        raise RuntimeError("In-memory databases do not have a filesystem backup path.")
    return Path(main).resolve()


def _logical_snapshot(path):
    """Return integrity, table row counts, and a private logical-data digest."""
    connection = sqlite3.connect(f"file:{Path(path).resolve().as_posix()}?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        digest = hashlib.sha256()
        schema_rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        digest.update(json.dumps(schema_rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        counts = {}
        tables = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        for table, create_sql in tables:
            quoted_table = '"' + table.replace('"', '""') + '"'
            rows = connection.execute(f"PRAGMA table_info({quoted_table})").fetchall()
            columns = [row[1] for row in rows]
            primary_key = sorted((row[5], row[1]) for row in rows if row[5])
            if primary_key:
                order_columns = [column for _ordinal, column in primary_key]
            elif create_sql and "WITHOUT ROWID" in create_sql.upper():
                order_columns = columns
            else:
                order_columns = ["rowid"]
            order_sql = ", ".join('"' + column.replace('"', '""') + '"' for column in order_columns)
            cursor = connection.execute(f"SELECT * FROM {quoted_table} ORDER BY {order_sql}")
            count = 0
            for row in cursor:
                # Hash canonicalized rows without ever returning or logging their content.
                normalized = [
                    {"blob": value.hex()} if isinstance(value, bytes) else value
                    for value in row
                ]
                digest.update(json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8"))
                digest.update(b"\n")
                count += 1
            counts[table] = count
        return integrity, counts, digest.hexdigest()
    finally:
        connection.close()


def create_verified_backup(output_path):
    """Create a non-overwriting SQLite backup and verify its logical contents."""
    source = _database_path()
    output = Path(output_path).expanduser().resolve()
    if output == source:
        raise RuntimeError("Backup output must be a different file from the active database.")
    if output.exists():
        raise RuntimeError("Backup output already exists; choose a new path so no file is overwritten.")
    output.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    destination = sqlite3.connect(str(output))
    try:
        source_connection.backup(destination)
    finally:
        destination.close()
        source_connection.close()
    source_check, source_counts, source_digest = _logical_snapshot(source)
    backup_check, backup_counts, backup_digest = _logical_snapshot(output)
    if (
        source_check != "ok"
        or backup_check != "ok"
        or source_counts != backup_counts
        or source_digest != backup_digest
    ):
        raise RuntimeError("The database backup did not pass integrity and data verification.")
    return {"path": str(output), "integrity": backup_check, "counts": backup_counts}


def verify_database_backup(backup_path):
    """Verify an existing backup matches the current database schema and data."""
    source = _database_path()
    backup = Path(backup_path).expanduser().resolve()
    if backup == source or not backup.is_file():
        raise RuntimeError("A separate, existing backup file is required.")
    source_check, source_counts, source_digest = _logical_snapshot(source)
    backup_check, backup_counts, backup_digest = _logical_snapshot(backup)
    if (
        source_check != "ok"
        or backup_check != "ok"
        or source_counts != backup_counts
        or source_digest != backup_digest
    ):
        raise RuntimeError("The backup failed integrity, schema, or data verification.")
    return {"path": str(backup), "integrity": backup_check, "counts": backup_counts}


def restore_backup_to_new_file(backup_path, destination_path):
    """Restore a verified backup to a new file without replacing an existing database."""
    backup = Path(backup_path).expanduser().resolve()
    destination = Path(destination_path).expanduser().resolve()
    if not backup.is_file() or destination.exists() or backup == destination:
        raise RuntimeError("Restore requires an existing backup and a new destination path.")
    source = sqlite3.connect(f"file:{backup.as_posix()}?mode=ro", uri=True)
    target = sqlite3.connect(str(destination))
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    integrity, counts, restored_digest = _logical_snapshot(destination)
    backup_integrity, backup_counts, backup_digest = _logical_snapshot(backup)
    if integrity != "ok" or backup_integrity != "ok" or counts != backup_counts or restored_digest != backup_digest:
        raise RuntimeError("The restored copy failed integrity or data verification.")
    return {"path": str(destination), "integrity": integrity, "counts": counts}
