"""Application factory for the Cybersecurity Toolkit."""
from flask import Flask

from .models import init_db
from .routes import main


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-this-secret-key"
    app.config["DATABASE"] = "app/instance/toolkit.sqlite3"

    app.register_blueprint(main)

    with app.app_context():
        init_db(app.config["DATABASE"])

    return app
