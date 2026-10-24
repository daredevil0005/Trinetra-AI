def verdict_for_score(score):
    """Map explainable points to a review priority, never a safety claim."""
    score = max(0, min(100, int(score)))
    if score == 0:
        return "Unassessed"
    if score <= 24:
        return "Low"
    if score <= 49:
        return "Suspicious"
    if score <= 74:
        return "High Risk"
    return "Critical"


def calculate_risk(query, query_type, heuristics=None, enrichment=None):
    """Score explicit review signals; domain words and TLDs carry no points."""
    del query, query_type  # Kept in the public signature for existing callers.
    evidence = []
    points = 0

    for item in heuristics or []:
        weight = max(0, min(100, int(item.get("weight", 0))))
        points += weight
        evidence.append({**item, "source": "local_heuristic", "risk_weight": weight})

    for provider in enrichment or []:
        for item in provider.get("findings", []):
            weight = max(0, min(100, int(item.get("risk_weight", 0))))
            points += weight
            evidence.append({**item, "source": provider.get("provider", "external_provider"), "risk_weight": weight})

    score = max(0, min(100, points))
    verdict = verdict_for_score(score)
    if score == 0:
        explanation = "No scored review signals were observed. Reputation was not established; this is not a safe verdict."
    else:
        explanation = "Review priority is based on the listed local heuristics and/or provider findings; it is not proof of malicious activity."

    return {
        "score": score,
        "verdict": verdict,
        "evidence": evidence,
        "explanation": explanation,
    }
