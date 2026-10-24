from flask import Blueprint, render_template
from sqlalchemy.orm import joinedload

from app.database.models import ActivityLog
from app.security.auth import current_user, login_required


logs_bp = Blueprint("logs", __name__)


@logs_bp.get("/logs")
@login_required
def logs():
    events = (
        ActivityLog.query.filter_by(user_id=current_user().id)
        .options(joinedload(ActivityLog.investigation))
        .order_by(ActivityLog.created_at.desc(), ActivityLog.id.desc())
        .limit(100)
        .all()
    )
    return render_template("logs.html", events=events)
