import re


def analyze_domain(domain):

    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if re.match(domain_pattern, domain):

        return {
            "valid": True,
            "message": "Valid domain"
        }

    return {
        "valid": False,
        "message": "Invalid domain"
    }