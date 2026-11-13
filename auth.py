"""
auth.py
--------
Authentication + authorization helpers for the Flask app.

Features
    * Password hashing (werkzeug, scrypt/pbkdf2 - never stored in plain text)
    * Session-based login with a fresh session on every login (prevents
      session fixation) and an idle/absolute lifetime
    * Roles: "admin" (everything) and "analyst" (analyse traffic, manage alerts)
    * Brute-force protection: account lock after N failed attempts
    * CSRF protection for every POST request
    * Safe "next" redirects (no open-redirect)
"""

import hmac
import re
import secrets
from datetime import datetime
from database import _utcnow
from functools import wraps
from urllib.parse import urlparse, urljoin

from flask import session, request, redirect, url_for, flash, g, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
import database as db

ROLES = ("admin", "analyst")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")

# A real hash to compare against when the username does not exist, so a
# failed login takes about the same time either way (no user enumeration).
_DUMMY_HASH = generate_password_hash("not-a-real-password")


# ---------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------

def hash_password(password: str) -> str:
    return generate_password_hash(password)


def validate_password(password: str, username: str = "") -> str | None:
    """Return an error message if the password is too weak, else None."""
    if len(password) < Config.MIN_PASSWORD_LENGTH:
        return f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters long."
    if len(password) > 128:
        return "Password must be 128 characters or fewer."
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        return "Password must contain at least one letter and one number."
    if username and username.lower() in password.lower():
        return "Password must not contain your username."
    return None


def validate_username(username: str) -> str | None:
    if not USERNAME_RE.match(username):
        return "Username must be 3-30 characters: letters, numbers, dot, dash or underscore."
    return None


# ---------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------

def _is_locked(user) -> bool:
    locked_until = user.get("locked_until")
    if not locked_until:
        return False
    if isinstance(locked_until, str):
        try:
            locked_until = datetime.strptime(locked_until[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return False
    return locked_until > _utcnow()


def authenticate(username: str, password: str):
    """
    Returns (user, error_message). On success error_message is None.
    The message is intentionally generic for bad username / bad password.
    """
    generic = "Invalid username or password."
    user = db.get_user_by_username(username) if username else None

    if user is None:
        check_password_hash(_DUMMY_HASH, password)   # equalize timing
        return None, generic

    if _is_locked(user):
        return None, (f"Account temporarily locked after too many failed attempts. "
                      f"Try again in {Config.LOCKOUT_MINUTES} minutes.")

    if not check_password_hash(user["password_hash"], password):
        db.record_failed_login(user["id"], Config.MAX_FAILED_LOGINS, Config.LOCKOUT_MINUTES)
        return None, generic

    if not user["is_active"]:
        return None, "This account has been disabled. Contact an administrator."

    db.record_successful_login(user["id"])
    return user, None


def login_user(user):
    """Start a brand-new session for this user."""
    session.clear()                      # drop anything set before login
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True             # honours PERMANENT_SESSION_LIFETIME


def logout_user():
    session.clear()


def load_current_user():
    """Called before every request: put the logged-in user (if any) on g."""
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return
    try:
        user = db.get_user_by_id(user_id)
    except Exception:
        user = None
    # Re-check the DB each request so disabling/deleting a user takes effect
    # immediately instead of waiting for their session to expire.
    if user is None or not user["is_active"]:
        session.clear()
        return
    g.user = user


# ---------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------

def _wants_json():
    return request.path.startswith("/api/")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            if _wants_json():
                return jsonify({"success": False, "error": "Authentication required."}), 401
            flash("Please log in to continue.", "error")
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                if _wants_json():
                    return jsonify({"success": False, "error": "Forbidden."}), 403
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


admin_required = role_required("admin")


# ---------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------

def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def csrf_protect():
    """before_request hook: reject state-changing requests without a valid token."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            if _wants_json():
                return jsonify({"success": False, "error": "Invalid CSRF token."}), 400
            flash("Your session expired or the form was invalid. Please try again.", "error")
            return redirect(request.referrer or url_for("login"))


# ---------------------------------------------------------------
# Safe redirects
# ---------------------------------------------------------------

def safe_next_url(target: str | None) -> str | None:
    """Only allow redirects back to this same site."""
    if not target:
        return None
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    if test.scheme in ("http", "https") and ref.netloc == test.netloc:
        return target
    return None
