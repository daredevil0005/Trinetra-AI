from flask import Blueprint, render_template, request

from app.database.models import Investigation
from app.security.auth import current_user, login_required


history_bp = Blueprint("history", __name__)


@history_bp.get("/history")
@login_required
def history():
    query = Investigation.query.filter_by(owner_user_id=current_user().id)
    search = request.args.get("q", "").strip()[:120]
    indicator_type = request.args.get("type", "").strip().lower()
    verdict = request.args.get("verdict", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    page = max(1, min(page, 10000))

    if search:
        query = query.filter(Investigation.target.contains(search, autoescape=True))
    if indicator_type in {"domain", "ip", "url"}:
        query = query.filter_by(query_type=indicator_type)
    else:
        indicator_type = ""
    if verdict in {"Safe", "Suspicious", "High Risk", "Critical", "Low", "Unassessed"}:
        query = query.filter_by(verdict=verdict)
    else:
        verdict = ""

    total = query.count()
    per_page = 25
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    investigations = query.order_by(
        Investigation.created_at.desc(), Investigation.id.desc()
    ).offset((page - 1) * per_page).limit(per_page).all()
    return render_template(
        "history.html",
        investigations=investigations,
        search=search,
        selected_type=indicator_type,
        selected_verdict=verdict,
        page=page,
        pages=pages,
        total=total,
    )
