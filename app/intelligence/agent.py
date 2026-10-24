"""Deterministic, modular workflow for one user-requested investigation."""

from app.analyzers.domain.domain_analyzer import analyze_domain
from app.analyzers.ip.ip_analyzer import analyze_ip
from app.analyzers.url.url_analyzer import analyze_url
from app.intelligence.enrichment import enrich_indicator
from app.intelligence.risk_engine import calculate_risk


ANALYZERS = {
    "domain": analyze_domain,
    "ip": analyze_ip,
    "url": analyze_url,
}


def run_investigation(target, indicator_type, request_enrichment=False):
    analyzer = ANALYZERS.get(indicator_type)
    if analyzer is None:
        return {
            "valid": False,
            "status": "invalid",
            "message": "Enter a domain, IP address, or HTTP(S) URL.",
            "type": indicator_type,
            "normalized": None,
            "observations": [],
            "heuristics": [],
            "enrichment": [],
            "recommendations": [],
        }

    analysis = analyzer(target)
    if not analysis["valid"]:
        return {**analysis, "enrichment": []}

    normalized = analysis["normalized"]
    enrichment = enrich_indicator(normalized, indicator_type) if request_enrichment else []
    risk_result = calculate_risk(
        normalized,
        indicator_type,
        heuristics=analysis["heuristics"],
        enrichment=enrichment,
    )
    recommendation = list(analysis["recommendations"])
    if risk_result["verdict"] == "Critical":
        recommendation.insert(
            0,
            "Escalate for immediate analyst review and corroborate provider detections before taking response action.",
        )
    elif risk_result["verdict"] == "High Risk":
        recommendation.insert(
            0,
            "Prioritize corroboration using another trusted source and follow the relevant incident procedure.",
        )
    elif risk_result["verdict"] == "Suspicious":
        recommendation.insert(
            0,
            "Corroborate the listed signals and review their context before interacting with the indicator.",
        )
    elif risk_result["verdict"] == "Low":
        recommendation.insert(
            0,
            "Review the low-weight signals in context; they can occur on legitimate infrastructure.",
        )
    if analysis["heuristics"]:
        recommendation.insert(
            0,
            "Review the listed heuristic indicators in context; they are not evidence that the indicator is malicious.",
        )
    else:
        recommendation.insert(
            0,
            "No local heuristic concerns were found. This does not establish that the indicator is safe.",
        )
    if request_enrichment:
        recommendation.append("Treat third-party reputation as one source of context; provider coverage and accuracy vary.")

    local_count = len(analysis["heuristics"])
    if not request_enrichment:
        summary = (
            f"Static analysis recorded {local_count} heuristic indicator(s). "
            "No external reputation lookup was requested."
        )
    else:
        available = sum(item["status"] == "available" for item in enrichment)
        summary = (
            f"Static analysis recorded {local_count} heuristic indicator(s). "
            f"Optional enrichment was requested; {available} provider(s) returned data."
        )
    return {
        **analysis,
        "summary": summary,
        "risk_result": risk_result,
        "enrichment": enrichment,
        "recommendations": recommendation,
        "data_sources": [
            "Local syntax and metadata analysis; no DNS query, HTTP request to the target, TLS check, or active scan was performed."
        ] + (["VirusTotal and AbuseIPDB were queried only if configured; see each provider's status and limitations."] if request_enrichment else []),
    }
