"""Opt-in, bounded integrations with third-party reputation providers."""

import base64
import ipaddress
import os
from datetime import datetime, timezone
from urllib.parse import quote

import requests


TIMEOUT = (3, 8)
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _provider(provider, status, summary, limitations, findings=None):
    return {
        "provider": provider,
        "status": status,
        "checked_at": _now(),
        "summary": summary,
        "limitations": limitations,
        "findings": findings or [],
    }


def _virustotal_id(target, indicator_type):
    if indicator_type == "url":
        return "urls/" + base64.urlsafe_b64encode(target.encode("utf-8")).decode("ascii").rstrip("=")
    if indicator_type == "ip":
        return "ip_addresses/" + quote(target, safe="")
    if indicator_type == "domain":
        return "domains/" + quote(target, safe="")
    return None


def _query_virustotal(target, indicator_type):
    if indicator_type == "ip":
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            return _provider("VirusTotal", "not_applicable", "The target is not a valid IP address.", [])
        if not address.is_global:
            return _provider("VirusTotal", "skipped_scope", "No lookup was made for a private or special-use address.", ["Reputation lookups are intended for publicly routable indicators."])

    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return _provider(
            "VirusTotal", "not_configured", "No lookup was made.",
            ["Set VIRUSTOTAL_API_KEY to enable this provider."],
        )

    endpoint = _virustotal_id(target, indicator_type)
    if not endpoint:
        return _provider("VirusTotal", "not_applicable", "This indicator type is not supported by this provider.", [])

    try:
        response = requests.get(
            f"{VT_BASE}/{endpoint}",
            headers={"x-apikey": key, "Accept": "application/json"},
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        if response.status_code == 429:
            return _provider("VirusTotal", "rate_limited", "The provider rate limit was reached.", ["Retry later; provider quotas apply."])
        if response.status_code in (401, 403):
            return _provider("VirusTotal", "unavailable", "The provider rejected the configured credentials.", ["Check the API key and account permissions."])
        if response.status_code == 404:
            return _provider("VirusTotal", "no_record", "The provider returned no record for this indicator.", ["A missing provider record is not evidence that an indicator is safe."])
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(max(0, int(v or 0)) for v in stats.values() if isinstance(v, (int, float)))
        findings = []
        if malicious:
            weight = 75 if malicious >= 20 else 50 if malicious >= 10 else 25 if malicious >= 3 else 10
            findings.append({
                "name": "VirusTotal malicious detections",
                "detail": f"VirusTotal reported {malicious} malicious detection(s) across {total} analysis result(s).",
                "risk_weight": weight,
            })
        if suspicious:
            findings.append({
                "name": "VirusTotal suspicious detections",
                "detail": f"VirusTotal reported {suspicious} suspicious detection(s).",
                "risk_weight": 10 if suspicious < 3 else 20,
            })
        if not findings:
            summary = "No malicious or suspicious detections were reported in the available analysis."
        else:
            summary = "The provider returned reputation detections; review the counts and source context."
        return _provider(
            "VirusTotal", "available", summary,
            ["Community and vendor detections can be incomplete, delayed, or incorrect.", "A zero-detection result does not prove that an indicator is safe."],
            findings,
        )
    except requests.Timeout:
        return _provider("VirusTotal", "timeout", "The provider did not respond before the timeout.", ["No reputation conclusion is available."])
    except requests.RequestException:
        return _provider("VirusTotal", "unavailable", "The provider request failed.", ["No reputation conclusion is available; the failure details were not logged."])
    except (ValueError, TypeError, AttributeError):
        return _provider("VirusTotal", "invalid_response", "The provider returned an unreadable response.", ["No reputation conclusion is available."])


def _query_abuseipdb(target, indicator_type):
    if indicator_type != "ip":
        return _provider("AbuseIPDB", "not_applicable", "This provider accepts IP addresses only.", [])

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return _provider("AbuseIPDB", "not_applicable", "The target is not a valid IP address.", [])
    if not address.is_global:
        return _provider("AbuseIPDB", "skipped_scope", "No lookup was made for a private or special-use address.", ["AbuseIPDB reputation checks are intended for publicly routable IP addresses."])

    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        return _provider(
            "AbuseIPDB", "not_configured", "No lookup was made.",
            ["Set ABUSEIPDB_API_KEY to enable this provider."],
        )
    try:
        response = requests.get(
            ABUSEIPDB_CHECK,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": target, "maxAgeInDays": 90},
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        if response.status_code == 429:
            return _provider("AbuseIPDB", "rate_limited", "The provider rate limit was reached.", ["Retry later; provider quotas apply."])
        if response.status_code in (401, 403):
            return _provider("AbuseIPDB", "unavailable", "The provider rejected the configured credentials.", ["Check the API key and account permissions."])
        response.raise_for_status()
        data = response.json().get("data", {})
        confidence = max(0, min(100, int(data.get("abuseConfidenceScore", 0) or 0)))
        reports = max(0, int(data.get("totalReports", 0) or 0))
        findings = []
        if confidence >= 95:
            weight = 75
        elif confidence >= 75:
            weight = 50
        elif confidence >= 50:
            weight = 35
        elif confidence >= 25:
            weight = 20
        else:
            weight = 0
        if weight:
            findings.append({
                "name": "AbuseIPDB abuse confidence",
                "detail": f"AbuseIPDB reported an abuse confidence score of {confidence}/100 from {reports} report(s).",
                "risk_weight": weight,
            })
        summary = f"Abuse confidence: {confidence}/100; {reports} report(s) in the provider's response."
        return _provider(
            "AbuseIPDB", "available", summary,
            ["Community reports may be incomplete, stale, or incorrect.", "A low score does not prove that an IP address is safe."],
            findings,
        )
    except requests.Timeout:
        return _provider("AbuseIPDB", "timeout", "The provider did not respond before the timeout.", ["No reputation conclusion is available."])
    except requests.RequestException:
        return _provider("AbuseIPDB", "unavailable", "The provider request failed.", ["No reputation conclusion is available; the failure details were not logged."])
    except (ValueError, TypeError, AttributeError):
        return _provider("AbuseIPDB", "invalid_response", "The provider returned an unreadable response.", ["No reputation conclusion is available."])


def enrich_indicator(target, indicator_type):
    """Query configured providers only when the caller explicitly requests it."""
    return [
        _query_virustotal(target, indicator_type),
        _query_abuseipdb(target, indicator_type),
    ]
