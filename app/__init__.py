import secrets

import click
from flask import Flask, render_template
from sqlalchemy import func, select
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config.config import Config
from app.database.db import db
from app.database.migrations import (
    create_verified_backup,
    restore_backup_to_new_file,
    upgrade_database,
    verify_database_backup,
)
from app.database.models import AdminAuditLog, User
from app.security.auth import hash_password, normalize_username, validate_password, init_auth
from app.security.csrf import init_csrf
from app.routes.auth_routes import auth_bp
from app.routes.dashboard_routes import dashboard_bp
from app.routes.history_routes import history_bp
from app.routes.investigation_routes import investigation_bp
from app.routes.ioc_routes import ioc_bp
from app.routes.logs_routes import logs_bp
from app.routes.user_routes import users_bp


_PLACEHOLDER_SECRETS = {
    "replace-with-a-long-random-value",
    "change-me",
    "secret",
    "development",
    "changeme",
}
_PLACEHOLDER_MARKERS = (
    "replace-with",
    "change-me",
    "changeme",
    "your-secret",
    "your_secret",
    "example-key",
    "sample-key",
    "default-secret",
    "dev-secret",
    "test-secret",
)


def _is_weak_secret(secret):
    if not isinstance(secret, str):
        return True
    normalized = secret.strip().lower()
    return (
        len(secret.encode("utf-8")) < 32
        or normalized in _PLACEHOLDER_SECRETS
        or any(marker in normalized for marker in _PLACEHOLDER_MARKERS)
        or len(set(secret)) < 12
    )


def _validate_configuration(app):
    environment = app.config.get("TRINETRA_ENV", "production").strip().lower()
    if environment not in {"development", "production", "testing"}:
        raise RuntimeError("TRINETRA_ENV must be development, testing, or production.")
    app.config["TRINETRA_ENV"] = environment
    proxy_count = app.config.get("TRUSTED_PROXY_COUNT", 0)
    if not isinstance(proxy_count, int) or not 0 <= proxy_count <= 5:
        raise RuntimeError("TRUSTED_PROXY_COUNT must be an integer from 0 to 5.")

    secret = app.config.get("SECRET_KEY")
    if app.testing and not secret:
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)
    elif environment == "development" and not secret:
        # Ephemeral keys are deliberately allowed only in explicit development mode.
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)
    else:
        if _is_weak_secret(secret):
            raise RuntimeError("Set SECRET_KEY to a persistent random value of at least 32 bytes before starting Trinetra AI.")
    if environment == "production" and not app.config.get("SESSION_COOKIE_SECURE"):
        raise RuntimeError("SESSION_COOKIE_SECURE must be enabled in production; use explicit development mode for local HTTP.")
    if environment == "production" and not app.config.get("SESSION_COOKIE_HTTPONLY"):
        raise RuntimeError("SESSION_COOKIE_HTTPONLY must be enabled in production.")
    if environment == "production" and app.config.get("SESSION_COOKIE_SAMESITE") not in {"Lax", "Strict"}:
        raise RuntimeError("SESSION_COOKIE_SAMESITE must be Lax or Strict in production.")


def create_app(test_config=None):
    app = Flask(__name__, template_folder="../templates", static_folder="static")
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    _validate_configuration(app)
    if app.config["TRUSTED_PROXY_COUNT"]:
        count = app.config["TRUSTED_PROXY_COUNT"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=count, x_proto=count)

    db.init_app(app)
    init_auth(app)
    init_csrf(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(investigation_bp)
    app.register_blueprint(ioc_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(users_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
        )
        response.headers.setdefault("Cache-Control", "private, no-store")
        return response

    @app.errorhandler(400)
    @app.errorhandler(413)
    def request_error(error):
        return render_template(
            "error.html",
            title="Request could not be processed",
            message=error.description if isinstance(error, HTTPException) else "The request could not be processed.",
        ), error.code if isinstance(error, HTTPException) else 400

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to view this page.",
        ), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template(
            "error.html",
            title="Page not found",
            message="The requested page or investigation report does not exist.",
        ), 404

    @app.errorhandler(Exception)
    def safe_unexpected_error(error):
        if isinstance(error, HTTPException):
            return error
        db.session.rollback()
        # Do not attach exception text, traceback, request data, or SQL parameters.
        app.logger.error("request_failed")
        return render_template(
            "error.html",
            title="Something went wrong",
            message="The request could not be completed. Please retry or contact an administrator.",
        ), 500

    @app.cli.command("provision-admin")
    @click.argument("username")
    def provision_admin(username):
        """Create the first administrator using hidden interactive password entry."""
        from app.database.migrations import _ensure_foundation

        _ensure_foundation()
        if db.session.execute(select(func.count()).select_from(User)).scalar_one():
            raise click.ClickException("Accounts already exist; use administrator-managed account creation.")
        normalized = normalize_username(username)
        if not normalized:
            raise click.ClickException("Username must be 3–32 characters using letters, digits, dot, underscore, or hyphen.")
        password = click.prompt("Administrator password", hide_input=True, confirmation_prompt=True)
        error = validate_password(password)
        if error:
            raise click.ClickException(error)
        user = User(username=normalized, password_hash=hash_password(password), role="admin", is_active=True)
        db.session.add(user)
        db.session.commit()
        click.echo("Initial administrator account created.")

    @app.cli.command("provision-legacy-owner")
    @click.argument("username")
    def provision_legacy_owner(username):
        """Create a restricted standard account for existing legacy records."""
        from app.database.migrations import _ensure_foundation

        _ensure_foundation()
        active_admin = db.session.execute(
            select(User.id).where(User.role == "admin", User.is_active.is_(True)).limit(1)
        ).first()
        if not active_admin:
            raise click.ClickException("Provision an administrator before the designated legacy owner.")
        normalized = normalize_username(username)
        if not normalized:
            raise click.ClickException("Username must be 3–32 characters using letters, digits, dot, underscore, or hyphen.")
        if db.session.execute(select(User.id).where(User.username == normalized)).first():
            raise click.ClickException("That username is already in use.")
        password = click.prompt("Legacy-owner initial password", hide_input=True, confirmation_prompt=True)
        error = validate_password(password)
        if error:
            raise click.ClickException(error)
        user = User(
            username=normalized,
            password_hash=hash_password(password),
            role="user",
            is_active=True,
            must_change_password=True,
            is_legacy_owner=True,
        )
        db.session.add(user)
        db.session.flush()
        db.session.add(AdminAuditLog(
            actor_user_id=active_admin[0],
            subject_user_id=user.id,
            event_type="legacy.owner_provisioned",
            message="A restricted legacy-owner account was provisioned.",
        ))
        db.session.commit()
        click.echo("Restricted legacy-owner account created. Keep its credentials private and deliver them securely.")

    @app.cli.command("db-backup")
    @click.option("--output", required=True, type=click.Path(path_type=str))
    def db_backup(output):
        """Create and verify a new SQLite backup without overwriting a file."""
        try:
            result = create_verified_backup(output)
        except RuntimeError as error:
            raise click.ClickException(str(error)) from None
        click.echo(f"Verified SQLite backup created: {result['path']} (integrity={result['integrity']}, counts={result['counts']}).")

    @app.cli.command("db-upgrade")
    @click.option("--backup", required=True, type=click.Path(exists=True, dir_okay=False, path_type=str))
    @click.option("--legacy-owner", default=None, help="Existing active standard account to own all pre-authentication records.")
    def db_upgrade(backup, legacy_owner):
        """Verify a backup, then apply pending versioned schema migrations."""
        try:
            backup_result = verify_database_backup(backup)
            result = upgrade_database(legacy_owner)
        except RuntimeError as error:
            raise click.ClickException(str(error)) from None
        click.echo(f"Database schema is at version {result['version']}; verified backup integrity={backup_result['integrity']}.")
        if not result.get("already_current"):
            click.echo(f"Ownership migration preserved {result.get('investigations', 0)} investigation and {result.get('activity_logs', 0)} activity records.")

    @app.cli.command("db-restore-copy")
    @click.option("--backup", required=True, type=click.Path(exists=True, dir_okay=False, path_type=str))
    @click.option("--destination", required=True, type=click.Path(path_type=str))
    def db_restore_copy(backup, destination):
        """Restore a backup to a new path without replacing an existing database."""
        try:
            result = restore_backup_to_new_file(backup, destination)
        except RuntimeError as error:
            raise click.ClickException(str(error)) from None
        click.echo(f"Restore copy verified: {result['path']} (integrity={result['integrity']}, counts={result['counts']}).")

    return app
