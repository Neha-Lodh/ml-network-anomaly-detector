"""
app.py
-------
Main Flask application for the ML-Based Network Anomaly Detector.

Routes:
    /               Home page
    /dashboard      Dashboard with stats + charts (reads from MySQL)
    /traffic        Traffic Analysis page (CSV upload + run ML)
    /alerts         Alerts page (list of detected anomalies)
    /ml-model       ML Model info / retrain page
    /api/*          JSON endpoints used by the frontend JS / Chart.js
"""

import os
import uuid
import traceback
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

from config import Config
import database as db
from preprocessing import load_and_validate, clean_data, DataValidationError
from ml_predict import predict, models_exist, ModelNotTrainedError
import train_model as trainer

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS


# ---------------------------------------------------------------
# PAGE ROUTES
# ---------------------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html", models_ready=models_exist())


def _sanitize_stats(stats):
    """Convert DB-driver types (Decimal, datetime) into plain JSON-safe types."""
    for row in stats.get("traffic_activity", []):
        row["anomalies"] = int(row["anomalies"] or 0)
        ts = row["created_at"]
        row["created_at"] = ts.strftime("%Y-%m-%d %H:%M") if hasattr(ts, "strftime") else str(ts)[:16]
    return stats


@app.route("/dashboard")
def dashboard():
    try:
        stats = _sanitize_stats(db.get_dashboard_stats())
        recent_alerts = db.get_recent_alerts(6)
        db_error = None
    except Exception as e:
        stats = None
        recent_alerts = []
        db_error = str(e)
    return render_template(
        "dashboard.html", stats=stats, recent_alerts=recent_alerts, db_error=db_error
    )


@app.route("/traffic", methods=["GET"])
def traffic_analysis():
    return render_template("traffic_analysis.html", models_ready=models_exist())


@app.route("/traffic/upload", methods=["POST"])
def traffic_upload():
    if "csv_file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("traffic_analysis"))

    file = request.files["csv_file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("traffic_analysis"))

    if not allowed_file(file.filename):
        flash("Only .csv files are allowed.", "error")
        return redirect(url_for("traffic_analysis"))

    if not models_exist():
        flash("ML models are not trained yet. Go to the ML Model page and train first.", "error")
        return redirect(url_for("traffic_analysis"))

    save_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(save_path)

    try:
        df = load_and_validate(save_path)
        df_clean = clean_data(df)
        results = predict(df_clean)

        batch_id = str(uuid.uuid4())[:8]
        db.insert_traffic_and_alerts(results, batch_id)

        summary = {
            "batch_id": batch_id,
            "total": int(len(results)),
            "anomalies": int(results["is_anomaly"].sum()),
            "normal": int((~results["is_anomaly"]).sum()),
        }

        table_rows = results[[
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "duration", "packet_count", "bytes_transferred",
            "failed_connections", "is_anomaly", "risk_score",
            "risk_level", "explanation",
        ]].to_dict(orient="records")

        return render_template(
            "traffic_analysis.html",
            models_ready=True,
            summary=summary,
            rows=table_rows,
        )

    except DataValidationError as e:
        flash(f"CSV validation error: {e}", "error")
        return redirect(url_for("traffic_analysis"))
    except ModelNotTrainedError as e:
        flash(str(e), "error")
        return redirect(url_for("traffic_analysis"))
    except Exception as e:
        traceback.print_exc()
        flash(f"Something went wrong while processing the file: {e}", "error")
        return redirect(url_for("traffic_analysis"))
    finally:
        if os.path.exists(save_path):
            os.remove(save_path)


@app.route("/alerts")
def alerts_page():
    risk_filter = request.args.get("risk", "All")
    try:
        alerts = db.get_all_alerts(risk_level_filter=risk_filter)
        db_error = None
    except Exception as e:
        alerts = []
        db_error = str(e)
    return render_template(
        "alerts.html", alerts=alerts, risk_filter=risk_filter, db_error=db_error
    )


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert(alert_id):
    new_status = request.form.get("status", "Reviewed")
    try:
        db.update_alert_status(alert_id, new_status)
        flash("Alert status updated.", "success")
    except Exception as e:
        flash(f"Could not update alert: {e}", "error")
    return redirect(url_for("alerts_page"))


@app.route("/ml-model")
def ml_model_page():
    return render_template("ml_model.html", models_ready=models_exist())


@app.route("/ml-model/train", methods=["POST"])
def ml_model_train():
    try:
        trainer.main()
        flash("Models trained successfully on the sample dataset.", "success")
    except Exception as e:
        traceback.print_exc()
        flash(f"Training failed: {e}", "error")
    return redirect(url_for("ml_model_page"))


# ---------------------------------------------------------------
# JSON API (used by Chart.js on the dashboard)
# ---------------------------------------------------------------

@app.route("/api/dashboard-stats")
def api_dashboard_stats():
    try:
        stats = _sanitize_stats(db.get_dashboard_stats())
        return jsonify({"success": True, "data": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/health")
def health():
    ok, msg = db.test_connection()
    return jsonify({"db_connected": ok, "message": msg, "models_ready": models_exist()})


if __name__ == "__main__":
    app.run(debug=Config.FLASK_DEBUG, host="127.0.0.1", port=5000)
