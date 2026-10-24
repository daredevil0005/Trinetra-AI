import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    TRINETRA_ENV = os.getenv("TRINETRA_ENV", "production").strip().lower()
    SECRET_KEY = os.getenv("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///trinetra.db")

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    MAX_CONTENT_LENGTH = 1 * 1024 * 1024

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv(
        "SESSION_COOKIE_SECURE",
        "false" if TRINETRA_ENV == "development" else "true",
    ).strip().lower() in {"1", "true", "yes"}
    PERMANENT_SESSION_LIFETIME = 8 * 60 * 60
    SESSION_REFRESH_EACH_REQUEST = False
    TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "0"))
    DATABASE_SCHEMA_VERSION = 2
