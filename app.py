"""
app.py
-------
Main Flask application for the ML-Based Network Anomaly Detector.

Routes:
    /               Home page                              (public)
    /login /logout  Authentication                         (public / logged in)
    /setup          Create the first admin account         (only while no users exist)
    /register       Self-registration                      (only if ALLOW_REGISTRATION=True)
    /account        Change your own password               (login)
    /admin/users    User management                        (admin)
    /dashboard      Dashboard with stats + charts          (login)
    /traffic        Traffic Analysis page (CSV upload)     (login)
    /alerts         Alerts page                            (login)
    /ml-model       ML Model info page                     (login; retraining = admin)
    /api/*          JSON endpoints used by Chart.js        (login)
"""

import os
import uuid
import traceback
from datetime import timedelta
from flask import (Flask, render_template, request, jsonify, redirect, url_for,
                   flash, g, session)
from werkzeug.utils import secure_filename

from config import Config
import database as db
from preprocessing import load_and_validate, clean_data, DataValidationError
from ml_predict import predict, models_exist, ModelNotTrainedError
import train_model as trainer
import auth
from auth import login_required, admin_required

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Sessions are signed with SECRET_KEY - refuse to run with the public default
# unless we are in local debug mode.
if Config.SECRET_KEY == "dev-secret-key-change-me" and not Config.FLASK_DEBUG:
    raise RuntimeError(
        "Set a strong SECRET_KEY in your .env file before running with FLASK_DEBUG=False. "
        "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\""
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,        # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",       # basic cross-site request protection
    SESSION_COOKIE_SECURE=Config.SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=Config.SESSION_LIFETIME_MINUTES),
    MAX_CONTENT_LENGTH=Config.MAX_UPLOAD_SIZE_MB * 1024 * 1024,
)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS


# ---------------------------------------------------------------
# AUTH HOOKS
# ---------------------------------------------------------------

@app.before_request
def _before_request():
    auth.load_current_user()
    return auth.csrf_protect()


@app.after_request
def _no_cache_for_logged_in_pages(resp):
    # Stops the browser's Back button from showing protected pages after logout.
    if g.get("user") is not None:
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def _inject_auth():
    return {
        "csrf_token": auth.csrf_token,
        "current_user": g.get("user"),
        "registration_open": Config.ALLOW_REGISTRATION,
    }


@app.errorhandler(403)
def _forbidden(_e):
    return render_template("error.html", code=403,
                           message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def _not_found(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(413)
def _too_large(_e):
    flash(f"File is too large (max {Config.MAX_UPLOAD_SIZE_MB} MB).", "error")
    return redirect(url_for("traffic_analysis"))


# ---------------------------------------------------------------
# AUTH ROUTES
# ---------------------------------------------------------------

def _redirect_if_logged_in():
    if g.get("user") is not None:
        return redirect(url_for("dashboard"))
    return None


@app.route("/setup", methods=["GET", "POST"])
def setup():
    """One-time creation of the first administrator."""
    if db.count_users() > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        error = (auth.validate_username(username)
                 or auth.validate_password(password, username)
                 or (None if password == confirm else "Passwords do not match."))
        if error:
            flash(error, "error")
        else:
            db.create_user(username, auth.hash_password(password), role="admin")
            flash("Administrator account created. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    redirect_resp = _redirect_if_logged_in()
    if redirect_resp:
        return redirect_resp
    if db.count_users() == 0:
        return redirect(url_for("setup"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user, error = auth.authenticate(username, password)
        if error:
            flash(error, "error")
        else:
            nxt = auth.safe_next_url(request.args.get("next"))
            auth.login_user(user)
            flash(f"Welcome back, {user['username']}.", "success")
            return redirect(nxt or url_for("dashboard"))
    return render_template("login.html", next=request.args.get("next", ""))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    auth.logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if not Config.ALLOW_REGISTRATION:
        return redirect(url_for("login"))
    redirect_resp = _redirect_if_logged_in()
    if redirect_resp:
        return redirect_resp

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        error = (auth.validate_username(username)
                 or auth.validate_password(password, username)
                 or (None if password == confirm else "Passwords do not match.")
                 or ("That username is already taken." if db.get_user_by_username(username) else None))
        if error:
            flash(error, "error")
        else:
            # Self-registered accounts are always the lowest-privilege role.
            db.create_user(username, auth.hash_password(password), role="analyst")
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        error = None
        if not auth.check_password_hash(g.user["password_hash"], current):
            error = "Current password is incorrect."
        else:
            error = (auth.validate_password(new, g.user["username"])
                     or (None if new == confirm else "New passwords do not match."))
        if error:
            flash(error, "error")
        else:
            db.update_user_password(g.user["id"], auth.hash_password(new))
            auth.login_user(g.user)   # rotate the session after a credential change
            flash("Password updated.", "success")
            return redirect(url_for("account"))
    return render_template("account.html")


# ---------------------------------------------------------------
# ADMIN: user management
# ---------------------------------------------------------------

@app.route("/admin/users")
@admin_required
def admin_users():
    return render_template("admin_users.html", users=db.list_users(), roles=auth.ROLES)


@app.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "analyst")
    error = (auth.validate_username(username)
             or auth.validate_password(password, username)
             or (None if role in auth.ROLES else "Invalid role.")
             or ("That username is already taken." if db.get_user_by_username(username) else None))
    if error:
        flash(error, "error")
    else:
        db.create_user(username, auth.hash_password(password), role=role)
        flash(f"User '{username}' created.", "success")
    return redirect(url_for("admin_users"))


def _target_user_or_redirect(user_id):
    user = db.get_user_by_id(user_id)
    if user is None:
        flash("User not found.", "error")
    return user


def _would_remove_last_admin(user):
    return user["role"] == "admin" and user["is_active"] and db.count_active_admins() <= 1


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    user = _target_user_or_redirect(user_id)
    role = request.form.get("role", "")
    if user is None:
        pass
    elif role not in auth.ROLES:
        flash("Invalid role.", "error")
    elif role != "admin" and _would_remove_last_admin(user):
        flash("You cannot demote the last active administrator.", "error")
    else:
        db.update_user_role(user_id, role)
        flash(f"Role for '{user['username']}' set to {role}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/active", methods=["POST"])
@admin_required
def admin_toggle_active(user_id):
    user = _target_user_or_redirect(user_id)
    if user is None:
        pass
    elif user["is_active"] and _would_remove_last_admin(user):
        flash("You cannot disable the last active administrator.", "error")
    elif user["id"] == g.user["id"]:
        flash("You cannot disable your own account.", "error")
    else:
        db.set_user_active(user_id, not user["is_active"])
        flash(f"User '{user['username']}' {'disabled' if user['is_active'] else 'enabled'}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    user = _target_user_or_redirect(user_id)
    new = request.form.get("new_password", "")
    if user is not None:
        error = auth.validate_password(new, user["username"])
        if error:
            flash(error, "error")
        else:
            db.update_user_password(user_id, auth.hash_password(new))
            flash(f"Password for '{user['username']}' has been reset.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    user = _target_user_or_redirect(user_id)
    if user is None:
        pass
    elif user["id"] == g.user["id"]:
        flash("You cannot delete your own account.", "error")
    elif _would_remove_last_admin(user):
        flash("You cannot delete the last active administrator.", "error")
    else:
        db.delete_user(user_id)
        flash(f"User '{user['username']}' deleted.", "success")
    return redirect(url_for("admin_users"))


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
@login_required
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
@login_required
def traffic_analysis():
    return render_template("traffic_analysis.html", models_ready=models_exist())


@app.route("/traffic/upload", methods=["POST"])
@login_required
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
        flash("ML models are not trained yet. Ask an administrator to train them from the ML Model page first.", "error")
        return redirect(url_for("traffic_analysis"))

    # Never trust the client-supplied filename (path traversal / overwrites):
    # sanitize it and prefix a random id so concurrent uploads can't collide.
    safe_name = secure_filename(file.filename) or "upload.csv"
    save_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{safe_name}")
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
@login_required
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
@login_required
def update_alert(alert_id):
    new_status = request.form.get("status", "Reviewed")
    try:
        db.update_alert_status(alert_id, new_status)
        flash("Alert status updated.", "success")
    except Exception as e:
        flash(f"Could not update alert: {e}", "error")
    return redirect(url_for("alerts_page"))


@app.route("/ml-model")
@login_required
def ml_model_page():
    return render_template("ml_model.html", models_ready=models_exist())


@app.route("/ml-model/train", methods=["POST"])
@admin_required
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
@login_required
def api_dashboard_stats():
    try:
        stats = _sanitize_stats(db.get_dashboard_stats())
        return jsonify({"success": True, "data": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/health")
def health():
    ok, msg = db.test_connection()
    if g.get("user") is None:
        # Don't leak DB error text / backend details to anonymous visitors.
        return jsonify({"status": "ok" if ok else "degraded"})
    return jsonify({"db_connected": ok, "message": msg, "models_ready": models_exist()})


if __name__ == "__main__":
    app.run(debug=Config.FLASK_DEBUG, host="127.0.0.1", port=5000)
