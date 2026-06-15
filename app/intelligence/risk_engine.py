def calculate_risk(query, query_type):

    score = 0

    evidence = []

    if query_type == "domain":

        domain = query.lower()

        suspicious_keywords = [
            "login",
            "secure",
            "verify",
            "update",
            "bank",
            "account",
            "paypal",
            "wallet",
            "crypto"
        ]

        for keyword in suspicious_keywords:

            if keyword in domain:

                score += 15

                evidence.append(
                    f"Contains suspicious keyword: {keyword}"
                )

        suspicious_tlds = [
            ".xyz",
            ".top",
            ".tk",
            ".ml",
            ".click"
        ]

        for tld in suspicious_tlds:

            if domain.endswith(tld):

                score += 25

                evidence.append(
                    f"Suspicious TLD detected: {tld}"
                )

        if len(domain) > 25:

            score += 15

            evidence.append(
                "Unusually long domain name"
            )

    if score <= 20:
        verdict = "Safe"

    elif score <= 50:
        verdict = "Suspicious"

    elif score <= 80:
        verdict = "High Risk"

    else:
        verdict = "Critical"

    return {
        "score": score,
        "verdict": verdict,
        "evidence": evidence
    }