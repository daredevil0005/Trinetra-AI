import re
import ipaddress


def detect_type(query):

    query = query.strip()

    # IP Address
    try:
        ipaddress.ip_address(query)
        return "ip"
    except ValueError:
        pass

    # URL
    url_pattern = r"^https?://"

    if re.match(url_pattern, query):
        return "url"

    # Domain
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if re.match(domain_pattern, query):
        return "domain"

    return "unknown"