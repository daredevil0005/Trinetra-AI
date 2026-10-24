import re


LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_domain(value):
    """Return an ASCII IDNA hostname after syntax validation."""
    if not isinstance(value, str):
        raise ValueError("Enter a domain name.")

    candidate = value.strip().rstrip(".")
    if not candidate or len(candidate) > 253 or any(ch.isspace() for ch in candidate):
        raise ValueError("Enter a domain name with valid length and no spaces.")
    if any(ch in candidate for ch in "/\\:@?#[]"):
        raise ValueError("Enter a domain only, without a scheme, path, or port.")

    try:
        ascii_domain = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The domain contains an invalid internationalized name.") from exc

    if len(ascii_domain) > 253:
        raise ValueError("The normalized domain is longer than 253 characters.")
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("The domain labels are not valid DNS hostname labels.")
    if len(labels[-1]) < 2 or not labels[-1][0].isalpha() or labels[-1].isdigit():
        raise ValueError("The domain must end with a non-numeric top-level label.")
    if all(label.isdigit() for label in labels):
        raise ValueError("A dotted numeric address must be entered as an IP address.")

    return ascii_domain


def analyze_domain(domain):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        return {
            "valid": False,
            "type": "domain",
            "normalized": None,
            "status": "invalid",
            "message": str(exc),
            "observations": [],
            "heuristics": [],
            "recommendations": [],
        }

    observations = [{
        "name": "Hostname syntax",
        "detail": "The value is syntactically valid as a domain name. No DNS lookup was performed.",
    }]
    heuristics = []
    labels = normalized.split(".")
    if any(label.startswith("xn--") for label in labels):
        heuristics.append({
            "name": "Internationalized hostname encoding",
            "detail": "At least one hostname label uses Punycode. This can be legitimate and is not evidence of malicious activity.",
            "weight": 10,
        })
    if len(normalized) > 40:
        heuristics.append({
            "name": "Long hostname",
            "detail": "The normalized hostname is longer than 40 characters; length alone does not establish risk.",
            "weight": 5,
        })
    if len(labels) > 4:
        heuristics.append({
            "name": "Many hostname labels",
            "detail": "The hostname contains more than four labels; this may be normal for some services.",
            "weight": 5,
        })

    return {
        "valid": True,
        "type": "domain",
        "normalized": normalized,
        "status": "completed",
        "message": "Valid domain syntax; reputation and DNS were not checked.",
        "observations": observations,
        "heuristics": heuristics,
        "recommendations": [
            "Confirm the domain with an authoritative source before relying on it.",
            "Request optional reputation enrichment if you need third-party context.",
        ],
    }
