from flask import Blueprint, render_template

from app.database.models.investigation import Investigation

dashboard_bp = Blueprint(
    "dashboard",
    __name__
)


@dashboard_bp.route("/")
def dashboard():

    investigations = Investigation.query.order_by(
        Investigation.created_at.desc()
    ).all()

    total_investigations = len(investigations)

    safe_count = Investigation.query.filter_by(
        verdict="Safe"
    ).count()

    suspicious_count = Investigation.query.filter_by(
        verdict="Suspicious"
    ).count()

    high_risk_count = Investigation.query.filter_by(
        verdict="High Risk"
    ).count()

    critical_count = Investigation.query.filter_by(
        verdict="Critical"
    ).count()

    return render_template(
        "dashboard/dashboard.html",
        investigations=investigations,
        total_investigations=total_investigations,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        high_risk_count=high_risk_count,
        critical_count=critical_count
    )