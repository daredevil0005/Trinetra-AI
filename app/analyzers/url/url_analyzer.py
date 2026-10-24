import ipaddress
from urllib.parse import urlsplit, urlunsplit

from app.analyzers.domain.domain_analyzer import normalize_domain


def analyze_url(value):
    invalid = {
        "valid": False,
        "type": "url",
        "normalized": None,
        "status": "invalid",
        "observations": [],
        "heuristics": [],
        "recommendations": [],
    }
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 2048:
        return {**invalid, "message": "Enter a URL up to 2,048 characters long."}

    candidate = value.strip()
    if any(ord(ch) < 32 for ch in candidate) or any(ch.isspace() for ch in candidate):
        return {**invalid, "message": "URLs cannot contain whitespace or control characters."}

    try:
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in {"http", "https"}:
            return {**invalid, "message": "Only HTTP and HTTPS URLs are supported."}
        if not parts.netloc or parts.username is not None or parts.password is not None:
            return {**invalid, "message": "Enter an absolute HTTP(S) URL without embedded credentials."}
        host = parts.hostname
        if not host:
            return {**invalid, "message": "The URL must contain a valid hostname."}
        port = parts.port
        try:
            address = ipaddress.ip_address(host)
            normalized_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
            host_is_ip = True
            host_scope = "globally routable" if address.is_global else "private or special-use"
        except ValueError:
            normalized_host = normalize_domain(host)
            host_is_ip = False
            host_scope = None
    except (ValueError, UnicodeError):
        return {**invalid, "message": "The URL has an invalid hostname, port, or authority."}

    scheme = parts.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    netloc = normalized_host
    if port is not None and port != default_port:
        netloc = f"{normalized_host}:{port}"
    path = parts.path or "/"
    normalized = urlunsplit((scheme, netloc, path, parts.query, parts.fragment))

    observations = [{"name": "URL scheme", "detail": f"The URL uses {scheme.upper()}. No connection or TLS check was performed."}]
    heuristics = []
    if scheme == "http":
        heuristics.append({
            "name": "Unencrypted URL scheme",
            "detail": "The URL uses HTTP. This describes the URL only; it does not indicate that the host is malicious.",
            "weight": 10,
        })
    if host_is_ip:
        observations.append({"name": "URL host", "detail": f"The URL uses an IP literal classified as {host_scope}."})
        heuristics.append({
            "name": "IP literal in URL",
            "detail": "The URL host is an IP address rather than a domain name. This can be legitimate.",
            "weight": 15,
        })
    elif any(label.startswith("xn--") for label in normalized_host.split(".")):
        heuristics.append({
            "name": "Internationalized URL hostname",
            "detail": "The hostname contains a Punycode label; this can be legitimate and is not proof of abuse.",
            "weight": 10,
        })
    if port is not None and port != default_port:
        observations.append({"name": "URL port", "detail": f"The URL specifies non-default port {port}."})
        heuristics.append({
            "name": "Non-default URL port",
            "detail": "The URL specifies a non-default port. This is a review signal, not a verdict.",
            "weight": 10,
        })
    if len(normalized) > 120:
        heuristics.append({
            "name": "Long URL",
            "detail": "The URL is longer than 120 characters. Long URLs can be legitimate.",
            "weight": 5,
        })

    return {
        "valid": True,
        "type": "url",
        "normalized": normalized,
        "status": "completed",
        "message": "Valid URL syntax; no URL was fetched or scanned.",
        "observations": observations,
        "heuristics": heuristics,
        "recommendations": [
            "Do not open an untrusted URL directly; verify its context and destination first.",
            "Request optional reputation enrichment if you need third-party context.",
        ],
    }
