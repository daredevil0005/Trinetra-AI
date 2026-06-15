from flask import Flask

from app.config.config import Config
from app.database.db import db
from app.routes.dashboard_routes import dashboard_bp
from app.routes.investigation_routes import investigation_bp


def create_app():

    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="static"
    )

    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    app.register_blueprint(
        dashboard_bp
    )

    app.register_blueprint(
         investigation_bp
    )

    return app