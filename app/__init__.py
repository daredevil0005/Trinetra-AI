from sqlalchemy import inspect, text
from flask import Flask, render_template
from werkzeug.exceptions import HTTPException

from app.config.config import Config
from app.database.db import db
from app.database.models import ActivityLog, Investigation  # noqa: F401
from app.security.csrf import init_csrf

from app.routes.dashboard_routes import dashboard_bp
from app.routes.investigation_routes import investigation_bp
from app.routes.ioc_routes import ioc_bp
from app.routes.history_routes import history_bp
from app.routes.logs_routes import logs_bp


def _migrate_investigation_columns():
    """Add optional report fields without replacing the existing history table."""
    inspector = inspect(db.engine)
    if "investigations" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("investigations")}
    additions = {
        "analysis_status": "VARCHAR(32) NOT NULL DEFAULT 'legacy'",
        "summary": "TEXT",
        "evidence_json": "TEXT",
        "recommendations_json": "TEXT",
        "enrichment_json": "TEXT",
        "data_sources_json": "TEXT",
    }
    with db.engine.begin() as connection:
        for column_name, definition in additions.items():
            if column_name not in existing:
                connection.execute(text(f"ALTER TABLE investigations ADD COLUMN {column_name} {definition}"))


def create_app(test_config=None):
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="static"
    )

    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    init_csrf(app)

    with app.app_context():
        db.create_all()
        _migrate_investigation_columns()

    app.register_blueprint(
        dashboard_bp
    )

    app.register_blueprint(
        investigation_bp
    )

    app.register_blueprint(
        ioc_bp
    )
    app.register_blueprint(history_bp)
    app.register_blueprint(logs_bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
        )
        return response

    @app.errorhandler(400)
    @app.errorhandler(413)
    def request_error(error):
        return render_template(
            "error.html",
            title="Request could not be processed",
            message=error.description if isinstance(error, HTTPException) else "The request could not be processed.",
        ), error.code if isinstance(error, HTTPException) else 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template(
            "error.html",
            title="Page not found",
            message="The requested page or investigation report does not exist.",
        ), 404

    @app.errorhandler(500)
    def internal_error(_error):
        return render_template(
            "error.html",
            title="Something went wrong",
            message="The request could not be completed. Please retry or check the server log.",
        ), 500

    return app
