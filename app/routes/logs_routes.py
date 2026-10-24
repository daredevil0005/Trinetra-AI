from flask import Blueprint, render_template
from sqlalchemy.orm import joinedload

from app.database.models import ActivityLog


logs_bp = Blueprint("logs", __name__)


@logs_bp.get("/logs")
def logs():
    events = (
        ActivityLog.query.options(joinedload(ActivityLog.investigation))
        .order_by(ActivityLog.created_at.desc(), ActivityLog.id.desc())
        .limit(100)
        .all()
    )
    return render_template("logs.html", events=events)
