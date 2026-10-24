import os
import unittest
from unittest.mock import patch

import requests

from app.analyzers.domain.domain_analyzer import analyze_domain
from app.analyzers.ip.ip_analyzer import analyze_ip
from app.analyzers.url.url_analyzer import analyze_url
from app.intelligence.enrichment import enrich_indicator
from app.intelligence.risk_engine import calculate_risk, verdict_for_score
from app.intelligence.type_detector import detect_type
from app.ioc.extractor import extract_iocs


class IndicatorAnalysisTests(unittest.TestCase):
    def test_type_detection_and_normalization(self):
        self.assertEqual(detect_type(" 2001:4860:4860::8888 "), "ip")
        self.assertEqual(detect_type("https://Example.Org/a"), "url")
        self.assertEqual(detect_type("Example.Org."), "domain")
        self.assertEqual(detect_type("not an indicator"), "unknown")
        self.assertEqual(analyze_domain("ExAmple.Org.")["normalized"], "example.org")
        self.assertFalse(analyze_domain("example..org")["valid"])

    def test_ip_and_url_validation(self):
        self.assertEqual(analyze_ip("2001:4860:4860::8888")["normalized"], "2001:4860:4860::8888")
        self.assertFalse(analyze_ip("999.10.1.2")["valid"])
        normalized = analyze_url("HTTPS://Example.Org:443/a")["normalized"]
        self.assertEqual(normalized, "https://example.org/a")
        self.assertFalse(analyze_url("ftp://example.org")["valid"])
        self.assertFalse(analyze_url("https://user:pass@example.org/")["valid"])
        self.assertFalse(analyze_url("https://example.org:bad/")["valid"])

    def test_risk_boundaries_and_keyword_tld_neutrality(self):
        self.assertEqual(verdict_for_score(0), "Unassessed")
        self.assertEqual(verdict_for_score(1), "Low")
        self.assertEqual(verdict_for_score(24), "Low")
        self.assertEqual(verdict_for_score(25), "Suspicious")
        self.assertEqual(verdict_for_score(49), "Suspicious")
        self.assertEqual(verdict_for_score(50), "High Risk")
        self.assertEqual(verdict_for_score(74), "High Risk")
        self.assertEqual(verdict_for_score(75), "Critical")
        neutral = calculate_risk("secure-login.example.xyz", "domain")
        self.assertEqual(neutral["score"], 0)
        self.assertEqual(neutral["verdict"], "Unassessed")
        self.assertIn("not a safe verdict", neutral["explanation"])
        capped = calculate_risk("x", "domain", heuristics=[{"name": "one", "weight": 90}, {"name": "two", "weight": 90}])
        self.assertEqual(capped["score"], 100)
        self.assertEqual(capped["verdict"], "Critical")

    def test_ioc_extraction_validates_and_deduplicates(self):
        md5 = "a" * 32
        sha1 = "b" * 40
        sha256 = "c" * 64
        text = (
            "Domain EXAMPLE.org and example.org; url https://Example.net/path, "
            "again https://example.net/path. IPv4 8.8.8.8 and invalid 999.1.1.1; "
            "email Blue.Team+IR@Example.org; dates 2026.10.24, version 1.2.3 and v1.2.3-beta; "
            f"hashes {md5} {sha1} {sha256}"
        )
        result = extract_iocs(text)
        self.assertEqual(result["domains"], ["example.org"])
        self.assertEqual(result["urls"], ["https://example.net/path"])
        self.assertEqual(result["ips"], ["8.8.8.8"])
        self.assertEqual(result["emails"], ["blue.team+ir@example.org"])
        self.assertEqual(result["md5"], [md5])
        self.assertEqual(result["sha1"], [sha1])
        self.assertEqual(result["sha256"], [sha256])

    def test_enrichment_missing_keys_does_not_call_network(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "", "ABUSEIPDB_API_KEY": ""}), patch(
            "app.intelligence.enrichment.requests.get"
        ) as get:
            results = enrich_indicator("8.8.8.8", "ip")
        get.assert_not_called()
        self.assertEqual([item["status"] for item in results], ["not_configured", "not_configured"])

    def test_enrichment_skips_private_ip_even_with_credentials(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key", "ABUSEIPDB_API_KEY": "test-key"}), patch(
            "app.intelligence.enrichment.requests.get"
        ) as get:
            results = enrich_indicator("10.0.0.7", "ip")
        get.assert_not_called()
        self.assertEqual([item["status"] for item in results], ["skipped_scope", "skipped_scope"])

    def test_enrichment_provider_timeouts_are_reported(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key", "ABUSEIPDB_API_KEY": "test-key"}), patch(
            "app.intelligence.enrichment.requests.get", side_effect=requests.Timeout
        ) as get:
            results = enrich_indicator("8.8.8.8", "ip")
        self.assertEqual(get.call_count, 2)
        self.assertEqual([item["status"] for item in results], ["timeout", "timeout"])
        self.assertTrue(all("test-key" not in str(item) for item in results))

    def test_provider_rate_limit_and_url_is_never_fetched(self):
        class RateLimitedResponse:
            status_code = 429

        target = "https://indicator.example/private/path"
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key", "ABUSEIPDB_API_KEY": ""}), patch(
            "app.intelligence.enrichment.requests.get", return_value=RateLimitedResponse()
        ) as get:
            results = enrich_indicator(target, "url")
        self.assertEqual(results[0]["status"], "rate_limited")
        self.assertEqual(results[1]["status"], "not_applicable")
        request_url = get.call_args.args[0]
        self.assertTrue(request_url.startswith("https://www.virustotal.com/api/v3/urls/"))
        self.assertNotEqual(request_url, target)
        self.assertFalse(get.call_args.kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
