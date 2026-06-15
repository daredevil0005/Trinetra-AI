from flask import Blueprint
from flask import render_template
from flask import request

from app.database.db import db
from app.database.models.investigation import Investigation

from app.intelligence.type_detector import detect_type
from app.intelligence.risk_engine import calculate_risk

from app.analyzers.domain.domain_analyzer import analyze_domain
from app.analyzers.ip.ip_analyzer import analyze_ip
from app.analyzers.url.url_analyzer import analyze_url


investigation_bp = Blueprint(
    "investigation",
    __name__
)


@investigation_bp.route(
    "/investigate",
    methods=["GET", "POST"]
)
def investigate():

    if request.method == "POST":

        query = request.form.get("query")

        query_type = detect_type(query)

        if query_type == "domain":
            analysis = analyze_domain(query)

        elif query_type == "ip":
            analysis = analyze_ip(query)

        elif query_type == "url":
            analysis = analyze_url(query)

        else:
            analysis = {
                "valid": False,
                "message": "Unknown Input Type"
            }

        risk_result = calculate_risk(
            query,
            query_type
        )

        new_investigation = Investigation(
            target=query,
            query_type=query_type,
            risk_score=risk_result["score"],
            verdict=risk_result["verdict"]
        )

        db.session.add(new_investigation)
        db.session.commit()

        return render_template(
            "investigation/result.html",
            query=query,
            query_type=query_type,
            analysis=analysis,
            risk_result=risk_result
        )

    return render_template(
        "investigation/investigate.html"
    )


@investigation_bp.route(
    "/report/<int:investigation_id>"
)
def view_report(investigation_id):

    investigation = Investigation.query.get_or_404(
        investigation_id
    )

    return render_template(
        "investigation/view_report.html",
        investigation=investigation
    )