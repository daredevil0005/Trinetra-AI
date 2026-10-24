import secrets

from flask import Blueprint, flash, redirect, render_template, request, url_for
from sqlalchemy import func, or_, select, update

from app.database.db import db
from app.database.models import AdminAuditLog, User
from app.security.auth import administrator_required, current_user, hash_password, normalize_username


users_bp = Blueprint("users", __name__)


def _audit(event_type, message, subject=None):
    db.session.add(AdminAuditLog(
        actor_user_id=current_user().id,
        subject_user_id=subject.id if subject else None,
        event_type=event_type,
        message=message,
    ))


def _user_management_page(error=None, temporary_password=None, status=200):
    users = db.session.execute(select(User).order_by(User.username.asc())).scalars().all()
    audits = db.session.execute(
        select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc(), AdminAuditLog.id.desc()).limit(50)
    ).scalars().all()
    return render_template(
        "auth/users.html",
        users=users,
        audits=audits,
        error=error,
        temporary_password=temporary_password,
    ), status


@users_bp.get("/users")
@administrator_required
def list_users():
    return _user_management_page()


@users_bp.post("/users/create")
@administrator_required
def create_user():
    username = normalize_username(request.form.get("username", ""))
    role = request.form.get("role", "user")
    if not username:
        return _user_management_page("Use a 3–32 character username with letters, digits, dots, underscores, or hyphens.", status=400)
    if role not in {"admin", "user"}:
        return _user_management_page("Choose one of the supported account roles.", status=400)
    if db.session.execute(select(User.id).where(User.username == username)).first():
        return _user_management_page("That username is already in use.", status=400)

    temporary_password = secrets.token_urlsafe(24)
    user = User(
        username=username,
        password_hash=hash_password(temporary_password),
        role=role,
        is_active=True,
        must_change_password=True,
    )
    db.session.add(user)
    db.session.flush()
    _audit("user.created", "An account was created.", user)
    db.session.commit()
    return _user_management_page(
        "Account created. Copy the temporary password now and deliver it to the user through a separate secure channel.",
        temporary_password=temporary_password,
    )


@users_bp.post("/users/<int:user_id>/toggle")
@administrator_required
def toggle_user(user_id):
    target = db.session.get(User, user_id)
    if target is None:
        return _user_management_page("The requested account was not found.", status=404)
    actor = current_user()
    if target.id == actor.id and target.is_active:
        return _user_management_page("You cannot deactivate your own account.", status=400)
    if target.role == "admin" and target.is_active:
        active_admins = db.session.execute(
            select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True))
        ).scalar_one()
        if active_admins <= 1:
            return _user_management_page("The last active administrator cannot be deactivated.", status=400)

    will_activate = not target.is_active
    conditions = [User.id == target.id, User.is_active.is_(target.is_active)]
    if target.is_active:
        active_admin_count = (
            select(func.count())
            .select_from(User)
            .where(User.role == "admin", User.is_active.is_(True))
            .scalar_subquery()
        )
        conditions.extend([
            User.id != actor.id,
            or_(User.role != "admin", active_admin_count > 1),
        ])
    result = db.session.execute(
        update(User)
        .where(*conditions)
        .values(is_active=will_activate, session_version=User.session_version + 1)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.session.rollback()
        return _user_management_page("The account status change was not allowed; keep at least one active administrator.", status=400)
    event = "user.activated" if will_activate else "user.deactivated"
    _audit(event, "An account's active status changed.", target)
    db.session.commit()
    flash("Account status updated.", "success")
    return redirect(url_for("users.list_users"))


@users_bp.post("/users/<int:user_id>/reset-password")
@administrator_required
def reset_password(user_id):
    target = db.session.get(User, user_id)
    if target is None:
        return _user_management_page("The requested account was not found.", status=404)
    if target.id == current_user().id:
        return _user_management_page("Use the password-change page for your own account.", status=400)
    temporary_password = secrets.token_urlsafe(24)
    target.password_hash = hash_password(temporary_password)
    target.must_change_password = True
    target.session_version += 1
    _audit("user.password_reset", "A temporary password was issued.", target)
    db.session.commit()
    return _user_management_page(
        "Temporary password generated. Copy it now and deliver it through a separate secure channel.",
        temporary_password=temporary_password,
    )
