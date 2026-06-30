import re


def extract_iocs(text):

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    email_pattern = (
        r"\b[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    url_pattern = (
        r"https?://[^\s]+"
    )

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    )

    ips = list(set(
        re.findall(ip_pattern, text)
    ))

    emails = list(set(
        re.findall(email_pattern, text)
    ))

    urls = list(set(
        re.findall(url_pattern, text)
    ))

    domains = list(set(
        re.findall(domain_pattern, text)
    ))

    return {
        "ips": ips,
        "emails": emails,
        "urls": urls,
        "domains": domains
    }