from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit, urlunsplit

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from sqlalchemy import select

from app.database.db import db
from app.database.models import ActivityLog, User
from app.security.auth import (
    clear_login_throttle,
    current_user,
    hash_password,
    login_is_limited,
    normalize_username,
    record_login_failure,
    set_authenticated_session,
    validate_password,
    verify_password,
)


auth_bp = Blueprint("auth", __name__)


def _safe_next(value):
    if not value or any(ord(char) < 32 for char in value) or "\\" in value:
        return None
    parsed = urlsplit(value)
    decoded_path = unquote(parsed.path)
    if (
        parsed.scheme
        or parsed.netloc
        or not parsed.path.startswith("/")
        or parsed.path.startswith("//")
        or decoded_path.startswith("//")
        or "\\" in decoded_path
        or any(ord(char) < 32 for char in decoded_path)
    ):
        return None
    return urlunsplit(("", "", parsed.path, parsed.query, ""))


def _generic_login_failure(next_url, status=401):
    return render_template("auth/login.html", error="Invalid username or password.", next_url=next_url), status


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    user = current_user()
    if user:
        return redirect(url_for("auth.change_password" if user.must_change_password else "dashboard.dashboard"))
    next_url = _safe_next(request.values.get("next", ""))
    if request.method == "GET":
        return render_template("auth/login.html", next_url=next_url)

    raw_username = request.form.get("username", "")
    username = normalize_username(raw_username)
    password = request.form.get("password", "")
    if len(password) > 1024:
        password = ""

    if login_is_limited(username or raw_username[:32], request.remote_addr):
        return _generic_login_failure(next_url, 429)

    user = db.session.execute(select(User).where(User.username == username)).scalar_one_or_none() if username else None
    password_matches = verify_password(user, password)
    if not user or not password_matches or not user.is_active:
        db.session.rollback()
        record_login_failure(username or raw_username[:32], request.remote_addr)
        return _generic_login_failure(next_url)

    clear_login_throttle(username, request.remote_addr)
    user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.add(ActivityLog(user_id=user.id, event_type="auth.login_succeeded", message="A user signed in."))
    db.session.commit()
    set_authenticated_session(user)
    destination = next_url or url_for("dashboard.dashboard")
    if user.must_change_password:
        destination = url_for("auth.change_password")
    return redirect(destination)


@auth_bp.post("/logout")
def logout():
    user = current_user()
    if user:
        db.session.add(ActivityLog(user_id=user.id, event_type="auth.logout", message="A user signed out."))
        db.session.commit()
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
def change_password():
    user = current_user()
    if not user:
        return redirect(url_for("auth.login", next=request.path))
    if request.method == "GET":
        return render_template("auth/change_password.html")

    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    error = validate_password(new_password)
    if not verify_password(user, old_password):
        error = "The current password is incorrect."
    elif not error and new_password == old_password:
        error = "Choose a password different from the current password."
    elif not error and new_password != confirm_password:
        error = "The new passwords do not match."
    if error:
        return render_template("auth/change_password.html", error=error), 400

    user.password_hash = hash_password(new_password)
    user.session_version += 1
    user.must_change_password = False
    db.session.add(ActivityLog(user_id=user.id, event_type="auth.password_changed", message="A user changed their password."))
    db.session.commit()
    session.clear()
    flash("Password changed. Sign in again with your new password.", "success")
    return redirect(url_for("auth.login"))
