import os
from tempfile import TemporaryDirectory

from django.test import TestCase
from rest_framework.test import APIClient


class ReportsEndpointsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.tmpdir = TemporaryDirectory()
        os.environ["REPORT_EXPORT_DIR"] = self.tmpdir.name
        os.environ["REPORT_SIGNING_KEY"] = "unit-test-signing-key"

    def tearDown(self):
        self.tmpdir.cleanup()
        os.environ.pop("REPORT_EXPORT_DIR", None)
        os.environ.pop("REPORT_SIGNING_KEY", None)

    def test_reports_summary(self):
        response = self.client.get("/api/v1/reports/summary/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("scan_report", payload)
        self.assertIn("regional_report", payload)
        self.assertIn("national_report", payload)

    def test_reports_export_formats(self):
        json_response = self.client.get("/api/v1/reports/export/?type=scan&format=json")
        self.assertEqual(json_response.status_code, 200)

        csv_response = self.client.get("/api/v1/reports/export/?type=scan&format=csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response["Content-Type"], "text/csv")

        pdf_response = self.client.get("/api/v1/reports/export/?type=scan&format=pdf")
        self.assertEqual(pdf_response.status_code, 200)
        self.assertEqual(pdf_response["Content-Type"], "application/pdf")

    def test_signed_immutable_export_and_ledger(self):
        signed_response = self.client.get("/api/v1/reports/export/?type=scan&format=json&signed=1&immutable=1")
        self.assertEqual(signed_response.status_code, 200)
        signed_payload = signed_response.json()

        self.assertIn("report", signed_payload)
        self.assertIn("signature", signed_payload)
        signature = signed_payload["signature"]
        self.assertTrue(signature["immutable"])
        self.assertIn("sha256", signature)
        self.assertIn("signature", signature)
        self.assertIn("ledger_entry_id", signature)
        self.assertIn("chain_hash", signature)

        ledger_response = self.client.get(
            "/api/v1/reports/exports/ledger/?limit=10",
            HTTP_X_DEBUG_ROLE="compliance",
        )
        self.assertEqual(ledger_response.status_code, 200)
        ledger_payload = ledger_response.json()
        self.assertGreaterEqual(ledger_payload["count"], 1)
        self.assertIn("entries", ledger_payload)
        self.assertIn("integrity", ledger_payload)
        self.assertTrue(ledger_payload["integrity"]["ok"])
