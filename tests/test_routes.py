import os
import re
import unittest
from unittest.mock import patch

from app import create_app
from app.database.db import db
from app.database.models import ActivityLog, Investigation


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-only-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
        })
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()

    def token(self, path="/investigate"):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode("ascii")

    def post_investigation(self, query, **extra):
        return self.client.post("/investigate", data={
            "csrf_token": self.token(),
            "query": query,
            **extra,
        })

    def test_factory_blueprints_and_empty_dashboard(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No investigations yet", response.data)
        self.assertIn(b"0</strong>", response.data)
        self.assertEqual(self.client.get("/history").status_code, 200)
        self.assertEqual(self.client.get("/logs").status_code, 200)
        self.assertEqual(self.client.get("/ioc").status_code, 200)
        for path in ("/static/css/style.css", "/static/js/app.js"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            response.close()
        missing = self.client.get("/report/999")
        self.assertEqual(missing.status_code, 404)
        self.assertIn(b"Page not found", missing.data)

    def test_investigation_persistence_report_and_download(self):
        response = self.post_investigation("Example.ORG.")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Investigation report", response.data)
        self.assertIn(b"example.org", response.data)
        self.assertIn(b"Unassessed", response.data)
        with self.app.app_context():
            record = Investigation.query.one()
            record_id = record.id
            self.assertEqual(record.target, "example.org")
            self.assertEqual(record.query_type, "domain")
            self.assertEqual(record.analysis_status, "completed")
            self.assertTrue(record.summary)
            self.assertTrue(record.data_sources)
            self.assertEqual(ActivityLog.query.count(), 1)
        saved = self.client.get(f"/report/{record_id}")
        self.assertEqual(saved.status_code, 200)
        self.assertIn(b"Data sources and limitations", saved.data)
        download = self.client.get(f"/report/{record_id}/download")
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment;", download.headers["Content-Disposition"])
        self.assertIn(b"Trinetra AI Investigation Report", download.data)
        self.assertIn(b"no DNS query", download.data)

    def test_invalid_input_is_not_saved_and_logs_generic_error(self):
        response = self.post_investigation("999.999.999.999")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"non-numeric", response.data.lower())
        with self.app.app_context():
            self.assertEqual(Investigation.query.count(), 0)
            event = ActivityLog.query.one()
            self.assertEqual(event.event_type, "investigation.validation_failed")
            self.assertNotIn("999", event.message)
        self.assertIn(b"No target stored", self.client.get("/logs").data)

    def test_history_filters_and_dashboard_counts_use_stored_rows(self):
        self.assertEqual(self.post_investigation("example.org").status_code, 200)
        self.assertEqual(self.post_investigation("8.8.8.8").status_code, 200)
        history = self.client.get("/history?q=example.org&type=domain&verdict=Unassessed")
        self.assertEqual(history.status_code, 200)
        self.assertIn(b"example.org", history.data)
        self.assertNotIn(b"8.8.8.8", history.data)
        dashboard = self.client.get("/")
        self.assertIn(b"Total investigations", dashboard.data)
        self.assertIn(b"2</strong>", dashboard.data)

    def test_ioc_extraction_and_empty_state(self):
        md5 = "a" * 32
        text = f"8.8.8.8 999.1.1.1 EXAMPLE.org https://example.net/path {md5}"
        response = self.client.post("/ioc", data={"csrf_token": self.token("/ioc"), "threat_text": text})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"example.org", response.data)
        self.assertIn(b"8.8.8.8", response.data)
        self.assertIn(md5.encode(), response.data)
        self.assertIn(b"Copy all", response.data)
        empty = self.client.post("/ioc", data={"csrf_token": self.token("/ioc"), "threat_text": "dates 2026.10.24 version 1.2.3"})
        self.assertEqual(empty.status_code, 200)
        self.assertIn(b"0 validated indicators found", empty.data)
        with self.app.app_context():
            self.assertEqual(Investigation.query.count(), 0)

    def test_csrf_and_opt_in_enrichment(self):
        denied = self.client.post("/investigate", data={"query": "example.org"})
        self.assertEqual(denied.status_code, 400)
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "", "ABUSEIPDB_API_KEY": ""}), patch(
            "app.intelligence.enrichment.requests.get"
        ) as get:
            result = self.post_investigation("8.8.8.8", enrich="on")
        self.assertEqual(result.status_code, 200)
        get.assert_not_called()
        self.assertIn(b"not configured", result.data.lower())


if __name__ == "__main__":
    unittest.main()
