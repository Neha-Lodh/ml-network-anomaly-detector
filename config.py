"""
config.py
----------
Loads configuration from environment variables via .env.
"""

import os
from dotenv import load_dotenv

# Load .env from the project directory
load_dotenv()


class Config:

    # -----------------------------------------------------------
    # Flask
    # -----------------------------------------------------------

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "dev-secret-key-change-me"
    )

    FLASK_DEBUG = (
        os.getenv(
            "FLASK_DEBUG",
            "True"
        ).lower() == "true"
    )

    PORT = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )

    # -----------------------------------------------------------
    # MySQL
    # -----------------------------------------------------------

    DB_HOST = (
        os.getenv("DB_HOST")
        or os.getenv("MYSQLHOST")
        or "localhost"
    )

    DB_PORT = int(
        os.getenv("DB_PORT")
        or os.getenv("MYSQLPORT")
        or "3306"
    )

    DB_USER = (
        os.getenv("DB_USER")
        or os.getenv("MYSQLUSER")
        or "root"
    )

    DB_PASSWORD = (
        os.getenv("DB_PASSWORD")
        or os.getenv("MYSQLPASSWORD")
        or ""
    )

    DB_NAME = (
        os.getenv("DB_NAME")
        or os.getenv("MYSQLDATABASE")
        or "network_anomaly_db"
    )

    # -----------------------------------------------------------
    # Upload
    # -----------------------------------------------------------

    MAX_UPLOAD_SIZE_MB = int(
        os.getenv(
            "MAX_UPLOAD_SIZE_MB",
            "10"
        )
    )

    ALLOWED_EXTENSIONS = {
        "csv"
    }