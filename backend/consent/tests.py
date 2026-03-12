from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient


class ConsentValidationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.auth_headers = {"HTTP_X_DEBUG_ROLE": "analyst"}

    def test_reject_invalid_validity_window(self):
        now = timezone.now()
        response = self.client.post(
            "/api/v1/consent/grants/",
            {
                "requester_name": "Tester",
                "requester_email": "tester@example.com",
                "target": "203.0.113.10",
                "allowed_scanners": ["nmap"],
                "valid_from": now.isoformat(),
                "valid_until": (now - timedelta(minutes=1)).isoformat(),
            },
            format="json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_create_consent_success(self):
        now = timezone.now()
        response = self.client.post(
            "/api/v1/consent/grants/",
            {
                "requester_name": "Tester",
                "requester_email": "tester@example.com",
                "target": "203.0.113.10",
                "allowed_scanners": ["nmap", "openvas"],
                "valid_from": now.isoformat(),
                "valid_until": (now + timedelta(days=2)).isoformat(),
            },
            format="json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 201)
        self.assertIn("consent_id", response.json())
