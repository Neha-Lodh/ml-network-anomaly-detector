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

    # MySQL database
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "network_anomaly_db")

    # Upload settings
    MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
    ALLOWED_EXTENSIONS = {"csv"}
