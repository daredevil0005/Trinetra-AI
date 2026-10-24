import sqlite3
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import text

from app import create_app
from app.database.db import db
from app.database.migrations import (
    create_verified_backup,
    restore_backup_to_new_file,
    schema_version,
    upgrade_database,
    verify_database_backup,
)
from app.database.models import ActivityLog, User
from app.security.auth import hash_password


LEGACY_SCHEMA = """
CREATE TABLE investigations (
 id INTEGER PRIMARY KEY, target VARCHAR(255) NOT NULL, query_type VARCHAR(50) NOT NULL,
 risk_score INTEGER, verdict VARCHAR(50), created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 analysis_status VARCHAR(32) NOT NULL DEFAULT 'legacy', summary TEXT, evidence_json TEXT,
 recommendations_json TEXT, enrichment_json TEXT, data_sources_json TEXT
);
CREATE TABLE activity_logs (
 id INTEGER PRIMARY KEY, event_type VARCHAR(50) NOT NULL, message VARCHAR(255) NOT NULL,
 investigation_id INTEGER, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE SET NULL
);
"""


class OwnershipMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.database_path = self.root / "legacy.sqlite"
        connection = sqlite3.connect(self.database_path)
        connection.executescript(LEGACY_SCHEMA)
        for row_id in range(1, 16):
            connection.execute(
                "INSERT INTO investigations (id, target, query_type, risk_score, verdict, created_at, analysis_status) "
                "VALUES (?, ?, 'domain', 0, 'Unassessed', '2026-01-01 00:00:00', 'legacy')",
                (row_id, f"legacy-{row_id}.example"),
            )
        connection.execute(
            "INSERT INTO activity_logs (id, event_type, message, investigation_id, created_at) "
            "VALUES (1, 'investigation.completed', 'A legacy event.', 1, '2026-01-01 00:00:00')"
        )
        connection.commit()
        connection.close()

        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-only-secret-for-migration-tests",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{self.database_path.as_posix()}",
            "SESSION_COOKIE_SECURE": False,
            "TRINETRA_ENV": "testing",
        })
        with self.app.app_context():
            from app.database.migrations import _ensure_foundation
            _ensure_foundation()
            admin = User(username="migration-admin", password_hash=hash_password("migration admin password"), role="admin")
            owner = User(
                username="legacy-owner",
                password_hash=hash_password("legacy owner temporary password"),
                role="user",
                must_change_password=True,
                is_legacy_owner=True,
            )
            db.session.add_all([admin, owner])
            db.session.commit()
            self.owner_id = owner.id

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()
        self.temp_dir.cleanup()

    def test_legacy_records_are_preserved_owned_and_migration_is_repeatable(self):
        with self.app.app_context():
            with self.assertRaisesRegex(RuntimeError, "standard legacy-owner account"):
                upgrade_database()
            self.assertEqual(schema_version(), 1)
            result = upgrade_database("legacy-owner")
            self.assertEqual(result["version"], 2)
            self.assertEqual(result["investigations"], 15)
            self.assertEqual(result["activity_logs"], 1)
            self.assertTrue(upgrade_database()["already_current"])

            counts = db.session.execute(text("SELECT COUNT(*), COUNT(DISTINCT owner_user_id) FROM investigations")).one()
            self.assertEqual(tuple(counts), (15, 1))
            owners = db.session.execute(text("SELECT COUNT(*) FROM investigations WHERE owner_user_id=:owner"), {"owner": self.owner_id}).scalar_one()
            self.assertEqual(owners, 15)
            activity = ActivityLog.query.one()
            self.assertEqual(activity.user_id, self.owner_id)
            self.assertEqual(activity.investigation.owner_user_id, self.owner_id)
            self.assertEqual(db.session.execute(text("PRAGMA foreign_key_check")).all(), [])

    def test_verified_backup_and_restore_copy_preserve_row_counts(self):
        with self.app.app_context():
            from app.database.migrations import _ensure_foundation
            _ensure_foundation()
            backup = create_verified_backup(self.root / "verified-backup.sqlite")
            self.assertEqual(backup["integrity"], "ok")
            self.assertEqual(backup["counts"]["investigations"], 15)
            self.assertEqual(backup["counts"]["activity_logs"], 1)
            self.assertEqual(backup["counts"]["users"], 2)
            restored = restore_backup_to_new_file(backup["path"], self.root / "restored-copy.sqlite")
            self.assertEqual(restored["integrity"], "ok")
            self.assertEqual(restored["counts"], backup["counts"])
            self.assertEqual(verify_database_backup(backup["path"])["integrity"], "ok")

            altered = self.root / "altered-backup.sqlite"
            source = sqlite3.connect(backup["path"])
            destination = sqlite3.connect(altered)
            try:
                source.backup(destination)
            finally:
                destination.close()
                source.close()
            altered_db = sqlite3.connect(altered)
            try:
                altered_db.execute("UPDATE investigations SET target='modified-copy.example' WHERE id=1")
                altered_db.commit()
            finally:
                altered_db.close()
            with self.assertRaisesRegex(RuntimeError, "integrity, schema, or data"):
                verify_database_backup(altered)
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                create_verified_backup(backup["path"])


if __name__ == "__main__":
    unittest.main()

