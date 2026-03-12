from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from consent.models import ConsentGrant


class ScanAuthorizationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.auth_headers = {"HTTP_X_DEBUG_ROLE": "analyst"}
        self.consent = ConsentGrant.objects.create(
            requester_name="Tester",
            requester_email="tester@example.com",
            target="203.0.113.0/24",
            allowed_scanners=["nmap", "openvas", "vulners"],
            valid_from=timezone.now(),
            valid_until=timezone.now() + timedelta(days=1),
            status="active",
        )

    def _create_scan_job(self, asset_value: str, scanner_type: str = "nmap") -> dict:
        response = self.client.post(
            "/api/v1/scans/jobs/",
            {
                "consent_id": str(self.consent.consent_id),
                "asset_type": "ip",
                "asset_value": asset_value,
                "scanner_type": scanner_type,
                "requested_by": "tester@example.com",
            },
            format="json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 201)
        return response.json()

    def test_reject_scan_outside_consent_scope(self):
        response = self.client.post(
            "/api/v1/scans/jobs/",
            {
                "consent_id": str(self.consent.consent_id),
                "asset_type": "ip",
                "asset_value": "203.0.114.10",
                "scanner_type": "nmap",
                "requested_by": "tester@example.com",
            },
            format="json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("outside authorized consent scope", response.json().get("detail", ""))

    def test_reject_disallowed_scanner(self):
        self.consent.allowed_scanners = ["nmap"]
        self.consent.save(update_fields=["allowed_scanners", "updated_at"])

        response = self.client.post(
            "/api/v1/scans/jobs/",
            {
                "consent_id": str(self.consent.consent_id),
                "asset_type": "ip",
                "asset_value": "203.0.113.10",
                "scanner_type": "openvas",
                "requested_by": "tester@example.com",
            },
            format="json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Scanner type not allowed", response.json().get("detail", ""))

    def test_allow_scan_within_scope_and_scanner(self):
        payload = self._create_scan_job("203.0.113.10", "nmap")
        self.assertEqual(payload["scanner_type"], "nmap")
        self.assertEqual(payload["asset"]["value"], "203.0.113.10")

    def test_scan_findings_endpoint_returns_distribution(self):
        self._create_scan_job("203.0.113.20", "openvas")
        process = self.client.post(
            "/api/v1/scans/jobs/process-once/",
            {"limit": 10},
            format="json",
            **self.auth_headers,
        )
        self.assertEqual(process.status_code, 200)

        response = self.client.get("/api/v1/scans/findings/?limit=50")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("findings", payload)
        self.assertIn("severity_distribution", payload)
        self.assertIn("open_ports", payload)

    def test_scan_job_progress_endpoint(self):
        payload = self._create_scan_job("203.0.113.30", "nmap")
        job_id = payload["scan_job_id"]

        initial = self.client.get(f"/api/v1/scans/jobs/{job_id}/progress/")
        self.assertEqual(initial.status_code, 200)
        self.assertEqual(initial.json()["status"], "queued")

        process = self.client.post(
            "/api/v1/scans/jobs/process-once/",
            {"limit": 10},
            format="json",
            **self.auth_headers,
        )
        self.assertEqual(process.status_code, 200)

        updated = self.client.get(f"/api/v1/scans/jobs/{job_id}/progress/")
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["status"], "completed")
