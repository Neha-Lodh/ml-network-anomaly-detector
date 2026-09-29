"""
app.py
-------
Main Flask application for the ML-Based Network Anomaly Detector.

Routes:
    /                   Home page
    /dashboard          Dashboard with stats + charts
    /traffic            Traffic Analysis page (CSV upload + run ML)
    /alerts             Alerts page
    /ml-model           ML Model info / retrain page
    /api/*              JSON endpoints
    /health             Database + ML health check
"""

import os
import uuid
import traceback

from dotenv import load_dotenv

# ---------------------------------------------------------------
# LOAD ENVIRONMENT VARIABLES
# ---------------------------------------------------------------

# Load .env before importing Config/database
load_dotenv()

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
)

from werkzeug.utils import secure_filename

from config import Config
import database as db

from preprocessing import (
    load_and_validate,
    clean_data,
    DataValidationError,
)

from ml_predict import (
    predict,
    models_exist,
    ModelNotTrainedError,
)

import train_model as trainer


# ---------------------------------------------------------------
# FLASK APP CONFIGURATION
# ---------------------------------------------------------------

app = Flask(__name__)

app.config.from_object(Config)

app.secret_key = Config.SECRET_KEY


# ---------------------------------------------------------------
# UPLOAD CONFIGURATION
# ---------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum upload size: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


# ---------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------

def allowed_file(filename):
    """
    Check whether the uploaded file has an allowed extension.
    """

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in Config.ALLOWED_EXTENSIONS
    )


def _sanitize_stats(stats):
    """
    Convert DB-driver types such as Decimal/datetime
    into JSON-safe Python types.
    """

    if not stats:
        return stats

    for row in stats.get("traffic_activity", []):

        if "anomalies" in row:
            row["anomalies"] = int(row["anomalies"])

        if row.get("created_at"):
            row["created_at"] = row["created_at"].strftime(
                "%Y-%m-%d %H:%M"
            )

    return stats


def generate_safe_filename(filename):
    """
    Generate a unique safe filename so that uploaded files
    cannot overwrite existing files.
    """

    original_name = secure_filename(filename)

    extension = ""

    if "." in original_name:
        extension = "." + original_name.rsplit(".", 1)[1].lower()

    unique_name = f"{uuid.uuid4().hex}{extension}"

    return unique_name


# ---------------------------------------------------------------
# PAGE ROUTES
# ---------------------------------------------------------------


@app.route("/")
def home():

    try:
        model_status = models_exist()
    except Exception:
        model_status = False

    return render_template(
        "home.html",
        models_ready=model_status
    )


# ---------------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------------

@app.route("/dashboard")
def dashboard():

    try:

        stats = _sanitize_stats(
            db.get_dashboard_stats()
        )

        recent_alerts = db.get_recent_alerts(6)

        db_error = None

    except Exception as e:

        traceback.print_exc()

        stats = None

        recent_alerts = []

        db_error = str(e)

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_alerts=recent_alerts,
        db_error=db_error,
    )


# ---------------------------------------------------------------
# TRAFFIC ANALYSIS PAGE
# ---------------------------------------------------------------

@app.route("/traffic", methods=["GET"])
def traffic_analysis():

    try:
        model_status = models_exist()
    except Exception:
        model_status = False

    return render_template(
        "traffic_analysis.html",
        models_ready=model_status
    )


# ---------------------------------------------------------------
# TRAFFIC CSV UPLOAD + ML ANALYSIS
# ---------------------------------------------------------------

@app.route("/traffic/upload", methods=["POST"])
def traffic_upload():

    # -----------------------------------------------------------
    # CHECK FILE FIELD
    # -----------------------------------------------------------

    if "csv_file" not in request.files:

        flash(
            "No file selected.",
            "error"
        )

        return redirect(
            url_for("traffic_analysis")
        )


    file = request.files["csv_file"]


    # -----------------------------------------------------------
    # CHECK EMPTY FILE
    # -----------------------------------------------------------

    if file.filename == "":

        flash(
            "No file selected.",
            "error"
        )

        return redirect(
            url_for("traffic_analysis")
        )


    # -----------------------------------------------------------
    # CHECK FILE TYPE
    # -----------------------------------------------------------

    if not allowed_file(file.filename):

        flash(
            "Only .csv files are allowed.",
            "error"
        )

        return redirect(
            url_for("traffic_analysis")
        )


    # -----------------------------------------------------------
    # CHECK ML MODELS
    # -----------------------------------------------------------

    try:

        if not models_exist():

            flash(
                "ML models are not trained yet. "
                "Go to the ML Model page and train first.",
                "error"
            )

            return redirect(
                url_for("traffic_analysis")
            )

    except Exception as e:

        traceback.print_exc()

        flash(
            f"Could not check ML models: {e}",
            "error"
        )

        return redirect(
            url_for("traffic_analysis")
        )


    # -----------------------------------------------------------
    # CREATE SAFE UNIQUE FILE PATH
    # -----------------------------------------------------------

    safe_filename = generate_safe_filename(
        file.filename
    )

    save_path = os.path.join(
        UPLOAD_FOLDER,
        safe_filename
    )


    # -----------------------------------------------------------
    # SAVE FILE
    # -----------------------------------------------------------

    try:

        file.save(save_path)

    except Exception as e:

        traceback.print_exc()

        flash(
            f"Could not save uploaded file: {e}",
            "error"
        )

        return redirect(
            url_for("traffic_analysis")
        )


    # -----------------------------------------------------------
    # PROCESS FILE
    # -----------------------------------------------------------

    try:

        # -------------------------------------------------------
        # LOAD + VALIDATE CSV
        # -------------------------------------------------------

        df = load_and_validate(
            save_path
        )


        # -------------------------------------------------------
        # CLEAN DATA
        # -------------------------------------------------------

        df_clean = clean_data(
            df
        )


        # -------------------------------------------------------
        # ML PREDICTION
        # -------------------------------------------------------

        results = predict(
            df_clean
        )


        # -------------------------------------------------------
        # GENERATE BATCH ID
        # -------------------------------------------------------

        batch_id = str(
            uuid.uuid4()
        )[:8]


        # -------------------------------------------------------
        # SAVE RESULTS TO DATABASE
        # -------------------------------------------------------

        db.insert_traffic_and_alerts(
            results,
            batch_id
        )


        # -------------------------------------------------------
        # SUMMARY
        # -------------------------------------------------------

        total_records = len(results)

        anomalies = int(
            results["is_anomaly"].sum()
        )

        normal = int(
            (~results["is_anomaly"]).sum()
        )


        summary = {

            "batch_id": batch_id,

            "total": int(
                total_records
            ),

            "anomalies": anomalies,

            "normal": normal,

        }


        # -------------------------------------------------------
        # TABLE DATA
        # -------------------------------------------------------

        columns = [

            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "duration",
            "packet_count",
            "bytes_transferred",
            "failed_connections",
            "is_anomaly",
            "risk_score",
            "risk_level",
            "explanation",

        ]


        table_rows = results[
            columns
        ].to_dict(
            orient="records"
        )


        # -------------------------------------------------------
        # SHOW RESULTS
        # -------------------------------------------------------

        return render_template(

            "traffic_analysis.html",

            models_ready=True,

            summary=summary,

            rows=table_rows,

        )


    # -----------------------------------------------------------
    # CSV VALIDATION ERROR
    # -----------------------------------------------------------

    except DataValidationError as e:

        traceback.print_exc()

        flash(
            f"CSV validation error: {e}",
            "error"
        )

        return redirect(
            url_for("traffic_analysis")
        )


    # -----------------------------------------------------------
    # MODEL ERROR
    # -----------------------------------------------------------

    except ModelNotTrainedError as e:

        traceback.print_exc()

        flash(
            str(e),
            "error"
        )

        return redirect(
            url_for("traffic_analysis")
        )


    # -----------------------------------------------------------
    # DATABASE ERROR
    # -----------------------------------------------------------

    except Exception as e:

        traceback.print_exc()

        error_message = str(e)

        # Give a clearer message for MySQL authentication errors

        if (
            "1045" in error_message
            or "Access denied" in error_message
        ):

            flash(
                "Database connection failed. "
                "Check your MySQL username and password "
                "in your .env/configuration.",
                "error"
            )

        else:

            flash(
                f"Something went wrong while processing "
                f"the file: {error_message}",
                "error"
            )

        return redirect(
            url_for("traffic_analysis")
        )


    # -----------------------------------------------------------
    # ALWAYS DELETE TEMPORARY UPLOAD
    # -----------------------------------------------------------

    finally:

        if os.path.exists(save_path):

            try:

                os.remove(save_path)

            except Exception:

                traceback.print_exc()


# ---------------------------------------------------------------
# ALERTS PAGE
# ---------------------------------------------------------------

@app.route("/alerts")
def alerts_page():

    risk_filter = request.args.get(
        "risk",
        "All"
    )

    try:

        alerts = db.get_all_alerts(
            risk_level_filter=risk_filter
        )

        db_error = None

    except Exception as e:

        traceback.print_exc()

        alerts = []

        db_error = str(e)

    return render_template(

        "alerts.html",

        alerts=alerts,

        risk_filter=risk_filter,

        db_error=db_error,

    )


# ---------------------------------------------------------------
# UPDATE ALERT STATUS
# ---------------------------------------------------------------

@app.route(
    "/alerts/<int:alert_id>/status",
    methods=["POST"]
)
def update_alert(alert_id):

    new_status = request.form.get(
        "status",
        "Reviewed"
    )

    try:

        db.update_alert_status(
            alert_id,
            new_status
        )

        flash(
            "Alert status updated.",
            "success"
        )

    except Exception as e:

        traceback.print_exc()

        flash(
            f"Could not update alert: {e}",
            "error"
        )

    return redirect(
        url_for("alerts_page")
    )


# ---------------------------------------------------------------
# ML MODEL PAGE
# ---------------------------------------------------------------

@app.route("/ml-model")
def ml_model_page():

    try:

        model_status = models_exist()

    except Exception:

        model_status = False

    return render_template(

        "ml_model.html",

        models_ready=model_status

    )


# ---------------------------------------------------------------
# TRAIN ML MODEL
# ---------------------------------------------------------------

@app.route(
    "/ml-model/train",
    methods=["POST"]
)
def ml_model_train():

    try:

        trainer.main()

        flash(
            "Models trained successfully "
            "on the sample dataset.",
            "success"
        )

    except Exception as e:

        traceback.print_exc()

        flash(
            f"Training failed: {e}",
            "error"
        )

    return redirect(
        url_for("ml_model_page")
    )


# ---------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------

@app.route("/api/dashboard-stats")
def api_dashboard_stats():

    try:

        stats = _sanitize_stats(
            db.get_dashboard_stats()
        )

        return jsonify({

            "success": True,

            "data": stats,

        })


    except Exception as e:

        traceback.print_exc()

        return jsonify({

            "success": False,

            "error": str(e),

        }), 500


# ---------------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------------

@app.route("/health")
def health():

    try:

        ok, msg = db.test_connection()

    except Exception as e:

        traceback.print_exc()

        ok = False

        msg = str(e)


    try:

        model_status = models_exist()

    except Exception:

        model_status = False


    return jsonify({

        "db_connected": bool(ok),

        "message": msg,

        "models_ready": bool(model_status),

        "status": (
            "healthy"
            if ok
            else "database_error"
        ),

    })


# ---------------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum allowed size is 10 MB.",
        "error"
    )

    return redirect(
        url_for("traffic_analysis")
    )


@app.errorhandler(500)
def internal_server_error(error):

    traceback.print_exc()

    return render_template(

        "home.html",

        models_ready=False,

        error_message=(
            "An internal server error occurred. "
            "Check the terminal for details."
        )

    ), 500


# ---------------------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------------------

if __name__ == "__main__":

    app.run(

        debug=Config.FLASK_DEBUG,

        host="0.0.0.0",

        port=Config.PORT

    )
