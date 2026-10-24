import ipaddress


def detect_type(query):
    """Classify an indicator candidate without claiming that it is valid."""
    if not isinstance(query, str):
        return "unknown"

    value = query.strip()
    if not value:
        return "unknown"

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if "://" in value:
        return "url"

    if "." in value and not any(char.isspace() for char in value):
        return "domain"

    return "unknown"
