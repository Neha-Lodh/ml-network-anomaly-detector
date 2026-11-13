"""
config.py
----------
Loads configuration from environment variables (via a local .env file).
NEVER hardcode real credentials here - this file only reads them.
"""

import os
from dotenv import load_dotenv

load_dotenv()  # reads variables from a .env file in the project root


class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

    # Authentication / sessions
    ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "False") == "True"
    MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "8"))
    MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "5"))
    LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
    SESSION_LIFETIME_MINUTES = int(os.getenv("SESSION_LIFETIME_MINUTES", "60"))
    # Set to True when served over HTTPS so the cookie is never sent over HTTP
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False") == "True"

    # MySQL database
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "network_anomaly_db")

    # Upload settings
    MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
    ALLOWED_EXTENSIONS = {"csv"}
