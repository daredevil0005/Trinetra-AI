import ipaddress


def analyze_ip(value):
    try:
        address = ipaddress.ip_address(value.strip())
    except (AttributeError, ValueError):
        return {
            "valid": False,
            "type": "ip",
            "normalized": None,
            "status": "invalid",
            "message": "Enter a valid IPv4 or IPv6 address.",
            "observations": [],
            "heuristics": [],
            "recommendations": [],
        }

    scope = "globally routable" if address.is_global else "private or special-use"
    return {
        "valid": True,
        "type": "ip",
        "normalized": address.compressed,
        "status": "completed",
        "message": "Valid IP syntax; no network probe or reputation lookup was performed.",
        "observations": [
            {"name": "Address family", "detail": f"IPv{address.version} address."},
            {"name": "Address scope", "detail": f"Python's address registry classifies this as {scope}; this is not a threat assessment."},
        ],
        "heuristics": [],
        "recommendations": [
            "Confirm the address and its context with an authoritative source.",
            "Request optional reputation enrichment if you need third-party context.",
        ],
    }
