import json
import logging

from flask import Blueprint, make_response, render_template, request

from app.database.db import db
from app.database.models import ActivityLog, Investigation
from app.intelligence.agent import run_investigation
from app.intelligence.type_detector import detect_type


investigation_bp = Blueprint(
    "investigation",
    __name__
)
logger = logging.getLogger(__name__)


def _log_activity(event_type, message, investigation_id=None):
    db.session.add(ActivityLog(
        event_type=event_type,
        message=message,
        investigation_id=investigation_id,
    ))


@investigation_bp.route(
    "/investigate",
    methods=["GET", "POST"]
)
def investigate():
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        enrich_requested = request.form.get("enrich") == "on"
        error = None
        if not query:
            error = "Enter a domain, IP address, or HTTP(S) URL."
        elif len(query) > 2048:
            error = "The indicator must be 2,048 characters or fewer."

        query_type = detect_type(query)
        if not error:
            try:
                analysis = run_investigation(query, query_type, request_enrichment=enrich_requested)
            except Exception:
                db.session.rollback()
                logger.exception("Indicator analysis failed")
                try:
                    _log_activity("investigation.failed", "An investigation could not be completed.")
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                return render_template(
                    "error.html",
                    title="Analysis could not be completed",
                    message="The analysis failed unexpectedly. No report was saved; please retry.",
                ), 500
            if not analysis["valid"]:
                error = analysis["message"]

        if error:
            _log_activity("investigation.validation_failed", "An investigation input failed validation.")
            db.session.commit()
            return render_template(
                "investigation/investigate.html",
                error=error,
                query=query,
                enrich_requested=enrich_requested,
            ), 400

        try:
            risk_result = analysis["risk_result"]
            evidence = [
                {"category": "observation", **item}
                for item in analysis["observations"]
            ] + [
                {"category": "heuristic", **item}
                for item in analysis["heuristics"]
            ] + [
                {"category": "provider", **item}
                for item in risk_result["evidence"]
                if item.get("source") != "local_heuristic"
            ]
            record = Investigation(
                target=analysis["normalized"],
                query_type=query_type,
                risk_score=risk_result["score"],
                verdict=risk_result["verdict"],
                analysis_status="completed",
                summary=analysis["summary"],
                evidence_json=json.dumps(evidence, ensure_ascii=False),
                recommendations_json=json.dumps(analysis["recommendations"], ensure_ascii=False),
                enrichment_json=json.dumps(analysis["enrichment"], ensure_ascii=False),
                data_sources_json=json.dumps(analysis["data_sources"], ensure_ascii=False),
            )
            db.session.add(record)
            db.session.flush()
            _log_activity("investigation.completed", "An investigation completed.", record.id)
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Investigation processing failed")
            try:
                _log_activity("investigation.failed", "An investigation could not be saved.")
                db.session.commit()
            except Exception:
                db.session.rollback()
            return render_template(
                "error.html",
                title="Investigation could not be saved",
                message="The investigation could not be saved. Please retry; no report was created.",
            ), 500

        return render_template(
            "investigation/result.html",
            investigation=record,
            analysis=analysis,
            risk_result=risk_result,
            evidence=evidence,
        )

    return render_template(
        "investigation/investigate.html"
    )


@investigation_bp.route(
    "/report/<int:investigation_id>"
)
def view_report(investigation_id):
    investigation = db.get_or_404(Investigation, investigation_id)
    return render_template("investigation/view_report.html", investigation=investigation)


@investigation_bp.get("/report/<int:investigation_id>/download")
def download_report(investigation_id):
    investigation = db.get_or_404(Investigation, investigation_id)
    lines = [
        "Trinetra AI Investigation Report",
        f"Target: {investigation.target}",
        f"Indicator type: {investigation.query_type}",
        f"Timestamp: {investigation.created_at or 'Unknown'}",
        f"Analysis status: {investigation.analysis_status}",
        f"Risk score: {investigation.risk_score}",
        f"Verdict: {investigation.verdict or 'Unassessed'}",
        f"Summary: {investigation.summary or 'Detailed analysis was not stored for this legacy investigation.'}",
        "",
        "Evidence:",
    ]
    lines.extend(f"- [{item.get('category', 'evidence')}] {item.get('name', 'Finding')}: {item.get('detail', '')}" for item in investigation.evidence)
    lines.append("\nRecommendations:")
    lines.extend(f"- {item}" for item in investigation.recommendations)
    lines.append("\nData sources and limitations:")
    lines.extend(f"- {item}" for item in investigation.data_sources)
    for provider in investigation.enrichment:
        lines.append(f"\n{provider.get('provider', 'Provider')} ({provider.get('status', 'unknown')}): {provider.get('summary', '')}")
        lines.extend(f"- Limitation: {item}" for item in provider.get("limitations", []))

    response = make_response("\n".join(lines))
    response.mimetype = "text/plain"
    response.headers["Content-Disposition"] = f'attachment; filename="trinetra-report-{investigation.id}.txt"'
    return response
