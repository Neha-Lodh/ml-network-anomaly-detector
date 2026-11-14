"""
database.py
------------
All database access for the project lives here.

The app tries MySQL first (using the credentials in your .env file).
If MySQL is not reachable (wrong password, server not running, database
missing and cannot be created), it AUTOMATICALLY falls back to a local
SQLite file (data/anomaly.db) so the app still runs on localhost with
zero setup.

Force a backend with DB_BACKEND in .env:
    DB_BACKEND=auto     (default: MySQL, else SQLite)
    DB_BACKEND=mysql    (MySQL only, error if it fails)
    DB_BACKEND=sqlite   (SQLite only)

IMPORTANT: every query uses parameterized placeholders (%s) - never
raw string formatting - to prevent SQL injection.
"""

import os
import sqlite3
from datetime import datetime

from config import Config

try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except ImportError:  # mysql connector not installed -> SQLite only
    mysql = None

    class MySQLError(Exception):
        pass

SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "anomaly.db")

_backend = None          # "mysql" or "sqlite" (decided once, on first use)
_backend_note = ""       # human-readable reason, shown by /health


# ---------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------

def _mysql_connect(with_db=True):
    kwargs = dict(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        connection_timeout=5,
    )
    if with_db:
        kwargs["database"] = Config.DB_NAME
    return mysql.connector.connect(**kwargs)


def _create_mysql_schema():
    """Create the database + tables in MySQL if they don't exist yet."""
    conn = _mysql_connect(with_db=False)
    cur = conn.cursor()
    cur.execute(
        f"CREATE DATABASE IF NOT EXISTS `{Config.DB_NAME}` "
        "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
    )
    cur.execute(f"USE `{Config.DB_NAME}`")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS traffic_records (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            upload_batch_id VARCHAR(64) NOT NULL,
            record_timestamp VARCHAR(64) NULL,
            src_ip VARCHAR(45) NOT NULL,
            dst_ip VARCHAR(45) NOT NULL,
            src_port INT NOT NULL,
            dst_port INT NOT NULL,
            protocol VARCHAR(10) NOT NULL,
            duration FLOAT NOT NULL,
            packet_count INT NOT NULL,
            bytes_transferred BIGINT NOT NULL,
            failed_connections INT NOT NULL DEFAULT 0,
            is_anomaly TINYINT(1) NOT NULL DEFAULT 0,
            risk_score INT NOT NULL DEFAULT 0,
            risk_level VARCHAR(10) NOT NULL DEFAULT 'Low',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_batch (upload_batch_id),
            INDEX idx_created_at (created_at),
            INDEX idx_risk_level (risk_level)
        ) ENGINE=InnoDB
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            traffic_record_id BIGINT NOT NULL,
            upload_batch_id VARCHAR(64) NOT NULL,
            src_ip VARCHAR(45) NOT NULL,
            dst_ip VARCHAR(45) NOT NULL,
            dst_port INT NOT NULL,
            protocol VARCHAR(10) NOT NULL,
            risk_score INT NOT NULL,
            risk_level VARCHAR(10) NOT NULL,
            explanation VARCHAR(500) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'New',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_alert_traffic FOREIGN KEY (traffic_record_id)
                REFERENCES traffic_records(id) ON DELETE CASCADE,
            INDEX idx_alert_batch (upload_batch_id),
            INDEX idx_alert_risk (risk_level)
        ) ENGINE=InnoDB
    """)
    conn.commit()
    cur.close()
    conn.close()


def _init_sqlite():
    os.makedirs(os.path.dirname(SQLITE_PATH), exist_ok=True)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS traffic_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_batch_id TEXT NOT NULL,
            record_timestamp TEXT,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            duration REAL NOT NULL,
            packet_count INTEGER NOT NULL,
            bytes_transferred INTEGER NOT NULL,
            failed_connections INTEGER NOT NULL DEFAULT 0,
            is_anomaly INTEGER NOT NULL DEFAULT 0,
            risk_score INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'Low',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_batch ON traffic_records(upload_batch_id);
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            traffic_record_id INTEGER NOT NULL,
            upload_batch_id TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            explanation TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (traffic_record_id) REFERENCES traffic_records(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_alert_batch ON alerts(upload_batch_id);
    """)
    conn.commit()
    conn.close()


def _decide_backend():
    """Pick MySQL or SQLite once, the first time the database is used."""
    global _backend, _backend_note
    if _backend:
        return _backend

    wanted = os.getenv("DB_BACKEND", "auto").strip().lower()

    if wanted != "sqlite" and mysql is not None:
        try:
            _create_mysql_schema()
            _mysql_connect().close()
            _backend, _backend_note = "mysql", "Connected to MySQL successfully."
            return _backend
        except Exception as e:
            if wanted == "mysql":
                raise
            print(f"[database] MySQL unavailable ({e}). Falling back to SQLite: {SQLITE_PATH}")
            _backend_note = f"MySQL unavailable ({e}). Using local SQLite database."
    elif wanted == "mysql":
        raise RuntimeError("mysql-connector-python is not installed.")
    else:
        _backend_note = "Using local SQLite database."

    _init_sqlite()
    _backend = "sqlite"
    return _backend


# ---------------------------------------------------------------
# Connection helpers (same interface for both backends)
# ---------------------------------------------------------------

def get_connection():
    if _decide_backend() == "mysql":
        return _mysql_connect()
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = lambda cur, row: {d[0]: row[i] for i, d in enumerate(cur.description)}
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _cursor(conn):
    if _backend == "mysql":
        return conn.cursor(dictionary=True)
    return conn.cursor()


def _sql(query):
    """Our queries are written with %s placeholders; SQLite needs ?"""
    return query if _backend == "mysql" else query.replace("%s", "?")


def _exec(cur, query, params=()):
    cur.execute(_sql(query), params)


def test_connection():
    """Used by /health to report which database is in use."""
    try:
        conn = get_connection()
        conn.close()
        return True, f"[{_backend}] {_backend_note}"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------
# INSERT: traffic records + alerts (called after each CSV upload)
# ---------------------------------------------------------------

def insert_traffic_and_alerts(results_df, batch_id: str):
    conn = get_connection()
    cursor = _cursor(conn)

    traffic_insert_sql = """
        INSERT INTO traffic_records
            (upload_batch_id, record_timestamp, src_ip, dst_ip, src_port,
             dst_port, protocol, duration, packet_count, bytes_transferred,
             failed_connections, is_anomaly, risk_score, risk_level)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    alert_insert_sql = """
        INSERT INTO alerts
            (traffic_record_id, upload_batch_id, src_ip, dst_ip, dst_port,
             protocol, risk_score, risk_level, explanation, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    try:
        for _, row in results_df.iterrows():
            _exec(
                cursor,
                traffic_insert_sql,
                (
                    batch_id,
                    str(row.get("timestamp", "")),
                    str(row["src_ip"]),
                    str(row["dst_ip"]),
                    int(row["src_port"]),
                    int(row["dst_port"]),
                    str(row["protocol"]),
                    float(row["duration"]),
                    int(row["packet_count"]),
                    int(row["bytes_transferred"]),
                    int(row["failed_connections"]),
                    int(bool(row["is_anomaly"])),
                    int(row["risk_score"]),
                    str(row["risk_level"]),
                ),
            )
            traffic_record_id = cursor.lastrowid

            if row["is_anomaly"]:
                _exec(
                    cursor,
                    alert_insert_sql,
                    (
                        traffic_record_id,
                        batch_id,
                        str(row["src_ip"]),
                        str(row["dst_ip"]),
                        int(row["dst_port"]),
                        str(row["protocol"]),
                        int(row["risk_score"]),
                        str(row["risk_level"]),
                        str(row["explanation"])[:500],
                        "New",
                    ),
                )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


# ---------------------------------------------------------------
# READ: dashboard statistics
# ---------------------------------------------------------------

def get_dashboard_stats():
    conn = get_connection()
    cursor = _cursor(conn)

    stats = {}

    _exec(cursor, "SELECT COUNT(*) AS total FROM traffic_records")
    stats["total_traffic"] = cursor.fetchone()["total"]

    _exec(cursor, "SELECT COUNT(*) AS total FROM traffic_records WHERE is_anomaly = 1")
    stats["total_anomalies"] = cursor.fetchone()["total"]

    stats["total_normal"] = stats["total_traffic"] - stats["total_anomalies"]

    if stats["total_traffic"] > 0:
        stats["anomaly_percentage"] = round(
            (stats["total_anomalies"] / stats["total_traffic"]) * 100, 2
        )
    else:
        stats["anomaly_percentage"] = 0.0

    _exec(cursor,
        """SELECT risk_level, COUNT(*) AS count
           FROM traffic_records GROUP BY risk_level""")
    risk_dist = {"Low": 0, "Medium": 0, "High": 0}
    for r in cursor.fetchall():
        risk_dist[r["risk_level"]] = r["count"]
    stats["risk_distribution"] = risk_dist

    _exec(cursor,
        """SELECT protocol, COUNT(*) AS count
           FROM traffic_records GROUP BY protocol""")
    stats["protocol_distribution"] = {r["protocol"]: r["count"] for r in cursor.fetchall()}

    _exec(cursor,
        """SELECT upload_batch_id,
                  COUNT(*) AS total,
                  SUM(is_anomaly) AS anomalies,
                  MIN(created_at) AS created_at
           FROM traffic_records
           GROUP BY upload_batch_id
           ORDER BY MIN(created_at) DESC
           LIMIT 15""")
    activity_rows = cursor.fetchall()
    activity_rows.reverse()
    stats["traffic_activity"] = activity_rows

    cursor.close()
    conn.close()
    return stats


def get_recent_alerts(limit: int = 10):
    conn = get_connection()
    cursor = _cursor(conn)
    _exec(cursor, "SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT %s", (limit,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_all_alerts(risk_level_filter=None, limit=200):
    conn = get_connection()
    cursor = _cursor(conn)
    if risk_level_filter and risk_level_filter != "All":
        _exec(cursor,
            """SELECT * FROM alerts WHERE risk_level = %s
               ORDER BY created_at DESC, id DESC LIMIT %s""",
            (risk_level_filter, limit))
    else:
        _exec(cursor, "SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT %s", (limit,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_traffic_records(limit: int = 100, batch_id: str = None):
    conn = get_connection()
    cursor = _cursor(conn)
    if batch_id:
        _exec(cursor,
            """SELECT * FROM traffic_records WHERE upload_batch_id = %s
               ORDER BY created_at DESC LIMIT %s""",
            (batch_id, limit))
    else:
        _exec(cursor, "SELECT * FROM traffic_records ORDER BY created_at DESC LIMIT %s", (limit,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def update_alert_status(alert_id: int, new_status: str):
    conn = get_connection()
    cursor = _cursor(conn)
    _exec(cursor, "UPDATE alerts SET status = %s WHERE id = %s", (new_status, alert_id))
    conn.commit()
    cursor.close()
    conn.close()
