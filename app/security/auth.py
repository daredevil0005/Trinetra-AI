"""Session authentication, password policy, and persistent login throttling."""

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import abort, current_app, flash, g, redirect, request, session, url_for
from sqlalchemy import case, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from werkzeug.security import check_password_hash, generate_password_hash

from app.database.db import db
from app.database.migrations import schema_version
from app.database.models import LoginThrottle, User


USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,30}[a-z0-9]$")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))
_PAIR_THRESHOLD = 5
_IP_THRESHOLD = 30
_WINDOW = timedelta(minutes=10)
_PAIR_COOLDOWN = timedelta(minutes=1)
_IP_COOLDOWN = timedelta(minutes=5)


def normalize_username(value):
    if not isinstance(value, str):
        return None
    username = value.strip().lower()
    if not 3 <= len(username) <= 32 or not USERNAME_RE.fullmatch(username):
        return None
    return username


def validate_password(value):
    if not isinstance(value, str) or not MIN_PASSWORD_LENGTH <= len(value) <= MAX_PASSWORD_LENGTH:
        return "Use a password between 12 and 128 characters."
    if not value.strip():
        return "Password cannot contain only spaces."
    return None


def hash_password(password):
    return generate_password_hash(password)


def verify_password(user, password):
    acceptable_input = isinstance(password, str) and len(password) <= MAX_PASSWORD_LENGTH
    candidate = password if acceptable_input else ""
    stored_hash = user.password_hash if user and acceptable_input else _DUMMY_PASSWORD_HASH
    try:
        valid = check_password_hash(stored_hash, candidate)
    except (TypeError, ValueError):
        valid = False
    return bool(user and acceptable_input and valid)


def set_authenticated_session(user):
    # Clearing the signed cookie before writing a new identity prevents fixation
    # and discards an anonymous CSRF token issued before authentication.
    session.clear()
    session.permanent = True
    session["_user_id"] = str(user.id)
    session["_session_version"] = user.session_version


def current_user():
    return getattr(g, "current_user", None)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("auth.login", next=request.full_path if request.query_string else request.path))
        if user.must_change_password and request.endpoint not in {"auth.change_password", "auth.logout"}:
            return redirect(url_for("auth.change_password"))
        return view(*args, **kwargs)
    return wrapped


def administrator_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user().is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def init_auth(app):
    @app.before_request
    def require_current_schema():
        if request.endpoint == "static":
            return None
        if schema_version() < current_app.config["DATABASE_SCHEMA_VERSION"]:
            return (
                "Database setup is incomplete. Run the documented backup and database-upgrade commands before using Trinetra AI.",
                503,
                {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"},
            )

    @app.before_request
    def load_authenticated_user():
        g.current_user = None
        user_id = session.get("_user_id")
        if user_id is None:
            return None
        try:
            user = db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            user = None
        if (
            user is None
            or not user.is_active
            or session.get("_session_version") != user.session_version
        ):
            session.clear()
            if request.endpoint not in {"auth.login", "static"}:
                return redirect(url_for("auth.login"))
            return None
        g.current_user = user
        return None

    @app.context_processor
    def inject_current_user():
        return {"current_user": current_user()}


def _throttle_digest(namespace, value):
    secret = current_app.secret_key
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, f"login:{namespace}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()


def _throttle_keys(username, remote_addr):
    ip = (remote_addr or "unknown")[:128]
    user_ip = f"{username or '(invalid)'}\0{ip}"
    return (
        (_throttle_digest("user-ip", user_ip), _PAIR_THRESHOLD, _PAIR_COOLDOWN),
        (_throttle_digest("ip", ip), _IP_THRESHOLD, _IP_COOLDOWN),
    )


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def login_is_limited(username, remote_addr, now=None):
    now = now or _utcnow()
    keys = [key for key, _limit, _cooldown in _throttle_keys(username, remote_addr)]
    with db.engine.connect() as connection:
        rows = connection.execute(
            select(LoginThrottle.blocked_until).where(LoginThrottle.bucket_key.in_(keys))
        ).scalars().all()
    return any(blocked_until is not None and blocked_until > now for blocked_until in rows)


def _upsert_failure(connection, key, threshold, cooldown, now):
    table = LoginThrottle.__table__
    cutoff = now - _WINDOW
    stale = table.c.window_started_at < cutoff
    next_failures = case((stale, 1), else_=table.c.failures + 1)
    block = case(
        (stale, None),
        (next_failures >= threshold, now + cooldown),
        else_=table.c.blocked_until,
    )
    values = {
        "bucket_key": key,
        "failures": 1,
        "window_started_at": now,
        "blocked_until": None,
    }
    dialect = connection.dialect.name
    if dialect == "sqlite":
        statement = sqlite_insert(table).values(**values)
        statement = statement.on_conflict_do_update(
            index_elements=[table.c.bucket_key],
            set_={
                "failures": next_failures,
                "window_started_at": case((stale, now), else_=table.c.window_started_at),
                "blocked_until": block,
            },
        )
        connection.execute(statement)
    elif dialect == "postgresql":
        statement = pg_insert(table).values(**values)
        connection.execute(statement.on_conflict_do_update(
            index_elements=[table.c.bucket_key],
            set_={
                "failures": next_failures,
                "window_started_at": case((stale, now), else_=table.c.window_started_at),
                "blocked_until": block,
            },
        ))
    else:
        row = connection.execute(
            select(
                table.c.failures,
                table.c.window_started_at,
                table.c.blocked_until,
            ).where(table.c.bucket_key == key).with_for_update()
        ).mappings().first()
        if row is None:
            connection.execute(table.insert().values(**values))
        else:
            expired = row.window_started_at < cutoff
            failures = 1 if expired else row.failures + 1
            connection.execute(update(table).where(table.c.bucket_key == key).values(
                failures=failures,
                window_started_at=now if expired else row.window_started_at,
                blocked_until=(None if expired else now + cooldown if failures >= threshold else row.blocked_until),
            ))


def record_login_failure(username, remote_addr, now=None):
    now = now or _utcnow()
    with db.engine.begin() as connection:
        connection.execute(
            delete(LoginThrottle).where(LoginThrottle.window_started_at < now - timedelta(days=1))
        )
        for key, threshold, cooldown in _throttle_keys(username, remote_addr):
            _upsert_failure(connection, key, threshold, cooldown, now)


def clear_login_throttle(username, remote_addr):
    keys = [key for key, _limit, _cooldown in _throttle_keys(username, remote_addr)]
    db.session.execute(delete(LoginThrottle).where(LoginThrottle.bucket_key.in_(keys)))
