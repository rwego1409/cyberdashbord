from django.test import TestCase
from rest_framework.test import APIClient


class OsintSourceHealthTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_sources_health_endpoint_shape(self):
        response = self.client.get("/api/v1/osint/sources-health/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("sources", payload)
        self.assertIn("total_events", payload)
        self.assertTrue(any(item["source"] == "tzcert" for item in payload["sources"]))
        self.assertTrue(any(item["source"] == "nvd" for item in payload["sources"]))
