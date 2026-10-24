import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from app.analyzers.domain.domain_analyzer import normalize_domain


URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'`]+")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[\w.-]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![\w@])(?:[\w-]+\.)+[\w-]+(?![\w-])", re.UNICODE)
HASH_PATTERNS = {
    "md5": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])"),
    "sha1": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])"),
    "sha256": re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])"),
}
URL_TRAILING_PUNCTUATION = ".,;:!?)]}"


def _add_unique(values, value, key=None):
    key = key or value.casefold()
    if key not in values["_keys"]:
        values["_keys"].add(key)
        values["items"].append(value)


def _valid_url(candidate):
    candidate = candidate.rstrip(URL_TRAILING_PUNCTUATION)
    try:
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
            return None
        if parts.username is not None or parts.password is not None or not parts.hostname:
            return None
        port = parts.port
        try:
            host_ip = ipaddress.ip_address(parts.hostname)
            host = f"[{host_ip.compressed}]" if host_ip.version == 6 else host_ip.compressed
        except ValueError:
            host = normalize_domain(parts.hostname)
        scheme = parts.scheme.lower()
        default_port = 443 if scheme == "https" else 80
        netloc = host if port is None or port == default_port else f"{host}:{port}"
        return urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))
    except (ValueError, UnicodeError):
        return None


def extract_iocs(text):
    """Extract validated, normalized indicator candidates without reputation checks."""
    groups = {
        key: {"items": [], "_keys": set()}
        for key in ("ips", "domains", "urls", "emails", "md5", "sha1", "sha256")
    }
    if not isinstance(text, str) or not text:
        return {key: [] for key in groups}

    protected_spans = []
    for match in URL_RE.finditer(text):
        value = _valid_url(match.group(0))
        if value:
            _add_unique(groups["urls"], value)
            protected_spans.append(match.span())

    for match in EMAIL_RE.finditer(text):
        candidate = match.group(0).rstrip(".,;:!?)]}")
        if len(candidate) > 254 or candidate.count("@") != 1:
            continue
        local, domain = candidate.rsplit("@", 1)
        if len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
            continue
        try:
            normalized = f"{local.lower()}@{normalize_domain(domain)}"
        except ValueError:
            continue
        _add_unique(groups["emails"], normalized)
        protected_spans.append(match.span())

    for match in IP_RE.finditer(text):
        try:
            address = ipaddress.IPv4Address(match.group(0))
        except ipaddress.AddressValueError:
            continue
        _add_unique(groups["ips"], str(address))

    for match in DOMAIN_RE.finditer(text):
        if any(match.start() < end and match.end() > start for start, end in protected_spans):
            continue
        try:
            domain = normalize_domain(match.group(0))
        except ValueError:
            continue
        _add_unique(groups["domains"], domain)

    for hash_type, pattern in HASH_PATTERNS.items():
        for match in pattern.finditer(text):
            _add_unique(groups[hash_type], match.group(0).lower())

    return {key: group["items"] for key, group in groups.items()}
