from flask import Blueprint, render_template
from sqlalchemy import or_

from app.database.models import Investigation

dashboard_bp = Blueprint(
    "dashboard",
    __name__
)


@dashboard_bp.route("/")
def dashboard():
    count = Investigation.query.count()
    counts = {
        verdict: Investigation.query.filter_by(verdict=verdict).count()
        for verdict in ("Safe", "Suspicious", "High Risk", "Critical")
    }
    unassessed_count = Investigation.query.filter(
        or_(
            Investigation.verdict.in_(("Unassessed", "Low")),
            Investigation.verdict.is_(None),
        )
    ).count()
    investigations = Investigation.query.order_by(
        Investigation.created_at.desc(), Investigation.id.desc()
    ).limit(10).all()
    return render_template(
        "dashboard/dashboard.html",
        investigations=investigations,
        total_investigations=count,
        safe_count=counts["Safe"],
        suspicious_count=counts["Suspicious"],
        high_risk_count=counts["High Risk"],
        critical_count=counts["Critical"],
        unassessed_count=unassessed_count,
    )
