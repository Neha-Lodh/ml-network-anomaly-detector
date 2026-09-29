"""
database.py
------------
All MySQL database access for the project lives here.

IMPORTANT:
- Every query uses parameterized placeholders (%s)
- Never use raw string formatting for SQL queries
- Database credentials are loaded through Config
"""

import mysql.connector
from mysql.connector import Error as MySQLError

from config import Config


# ---------------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------------

def get_connection():
    """
    Open a new MySQL connection using credentials from Config.
    """

    if not Config.DB_PASSWORD:
        raise RuntimeError(
            "MySQL password is missing. "
            "Please set DB_PASSWORD in your .env file."
        )

    try:

        conn = mysql.connector.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
        )

        return conn

    except MySQLError as e:

        raise RuntimeError(
            f"MySQL connection failed: {e}"
        ) from e


# ---------------------------------------------------------------
# TEST DATABASE CONNECTION
# ---------------------------------------------------------------

def test_connection():
    """
    Test whether MySQL is reachable.
    """

    conn = None

    try:

        conn = get_connection()

        return True, "Connected to MySQL successfully."

    except Exception as e:

        return False, str(e)

    finally:

        if conn is not None:

            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------
# INSERT: TRAFFIC RECORDS + ALERTS
# ---------------------------------------------------------------

def insert_traffic_and_alerts(results_df, batch_id: str):
    """
    Insert traffic records and anomalous records into MySQL.
    """

    conn = None
    cursor = None

    traffic_insert_sql = """
        INSERT INTO traffic_records
            (
                upload_batch_id,
                record_timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                duration,
                packet_count,
                bytes_transferred,
                failed_connections,
                is_anomaly,
                risk_score,
                risk_level
            )
        VALUES
            (%s, %s, %s, %s, %s, %s, %s,
             %s, %s, %s, %s, %s, %s, %s)
    """

    alert_insert_sql = """
        INSERT INTO alerts
            (
                traffic_record_id,
                upload_batch_id,
                src_ip,
                dst_ip,
                dst_port,
                protocol,
                risk_score,
                risk_level,
                explanation,
                status
            )
        VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    try:

        conn = get_connection()

        cursor = conn.cursor()

        for _, row in results_df.iterrows():

            cursor.execute(
                traffic_insert_sql,
                (
                    batch_id,

                    str(
                        row.get(
                            "timestamp",
                            ""
                        )
                    ),

                    str(row["src_ip"]),

                    str(row["dst_ip"]),

                    int(row["src_port"]),

                    int(row["dst_port"]),

                    str(row["protocol"]),

                    float(row["duration"]),

                    int(row["packet_count"]),

                    int(row["bytes_transferred"]),

                    int(row["failed_connections"]),

                    bool(row["is_anomaly"]),

                    int(row["risk_score"]),

                    str(row["risk_level"]),
                ),
            )

            traffic_record_id = cursor.lastrowid

            # ---------------------------------------------------
            # INSERT ALERT ONLY FOR ANOMALIES
            # ---------------------------------------------------

            if bool(row["is_anomaly"]):

                cursor.execute(
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

                        str(
                            row.get(
                                "explanation",
                                ""
                            )
                        )[:500],

                        "New",
                    ),
                )

        conn.commit()

    except Exception:

        if conn is not None:

            conn.rollback()

        raise

    finally:

        if cursor is not None:

            cursor.close()

        if conn is not None:

            conn.close()


# ---------------------------------------------------------------
# DASHBOARD STATISTICS
# ---------------------------------------------------------------

def get_dashboard_stats():

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor(
            dictionary=True
        )

        stats = {}

        # -------------------------------------------------------
        # TOTAL TRAFFIC
        # -------------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM traffic_records
            """
        )

        stats["total_traffic"] = (
            cursor.fetchone()["total"]
        )

        # -------------------------------------------------------
        # TOTAL ANOMALIES
        # -------------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM traffic_records
            WHERE is_anomaly = 1
            """
        )

        stats["total_anomalies"] = (
            cursor.fetchone()["total"]
        )

        stats["total_normal"] = (
            stats["total_traffic"]
            - stats["total_anomalies"]
        )

        # -------------------------------------------------------
        # ANOMALY PERCENTAGE
        # -------------------------------------------------------

        if stats["total_traffic"] > 0:

            stats["anomaly_percentage"] = round(
                (
                    stats["total_anomalies"]
                    / stats["total_traffic"]
                ) * 100,
                2
            )

        else:

            stats["anomaly_percentage"] = 0.0

        # -------------------------------------------------------
        # RISK DISTRIBUTION
        # -------------------------------------------------------

        cursor.execute(
            """
            SELECT
                risk_level,
                COUNT(*) AS count
            FROM traffic_records
            GROUP BY risk_level
            """
        )

        risk_rows = cursor.fetchall()

        risk_dist = {
            "Low": 0,
            "Medium": 0,
            "High": 0
        }

        for row in risk_rows:

            if row["risk_level"] in risk_dist:

                risk_dist[
                    row["risk_level"]
                ] = row["count"]

        stats["risk_distribution"] = risk_dist

        # -------------------------------------------------------
        # PROTOCOL DISTRIBUTION
        # -------------------------------------------------------

        cursor.execute(
            """
            SELECT
                protocol,
                COUNT(*) AS count
            FROM traffic_records
            GROUP BY protocol
            """
        )

        protocol_rows = cursor.fetchall()

        stats["protocol_distribution"] = {
            row["protocol"]: row["count"]
            for row in protocol_rows
        }

        # -------------------------------------------------------
        # TRAFFIC ACTIVITY
        # -------------------------------------------------------

        cursor.execute(
            """
            SELECT
                upload_batch_id,
                COUNT(*) AS total,
                SUM(is_anomaly) AS anomalies,
                MIN(created_at) AS created_at
            FROM traffic_records
            GROUP BY upload_batch_id
            ORDER BY created_at DESC
            LIMIT 15
            """
        )

        activity_rows = cursor.fetchall()

        activity_rows.reverse()

        stats["traffic_activity"] = (
            activity_rows
        )

        return stats

    finally:

        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()


# ---------------------------------------------------------------
# RECENT ALERTS
# ---------------------------------------------------------------

def get_recent_alerts(limit: int = 10):

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,)
        )

        return cursor.fetchall()

    finally:

        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()


# ---------------------------------------------------------------
# ALL ALERTS
# ---------------------------------------------------------------

def get_all_alerts(
    risk_level_filter=None,
    limit=200
):

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor(
            dictionary=True
        )

        if (
            risk_level_filter
            and risk_level_filter != "All"
        ):

            cursor.execute(
                """
                SELECT *
                FROM alerts
                WHERE risk_level = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (
                    risk_level_filter,
                    limit
                )
            )

        else:

            cursor.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,)
            )

        return cursor.fetchall()

    finally:

        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()


# ---------------------------------------------------------------
# TRAFFIC RECORDS
# ---------------------------------------------------------------

def get_traffic_records(
    limit: int = 100,
    batch_id: str = None
):

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor(
            dictionary=True
        )

        if batch_id:

            cursor.execute(
                """
                SELECT *
                FROM traffic_records
                WHERE upload_batch_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (
                    batch_id,
                    limit
                )
            )

        else:

            cursor.execute(
                """
                SELECT *
                FROM traffic_records
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,)
            )

        return cursor.fetchall()

    finally:

        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()


# ---------------------------------------------------------------
# UPDATE ALERT STATUS
# ---------------------------------------------------------------

def update_alert_status(
    alert_id: int,
    new_status: str
):

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE alerts
            SET status = %s
            WHERE id = %s
            """,
            (
                new_status,
                alert_id
            )
        )

        conn.commit()

    except Exception:

        if conn is not None:
            conn.rollback()

        raise

    finally:

        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()
