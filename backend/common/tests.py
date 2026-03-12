from django.test import TestCase
from rest_framework.test import APIClient


class SystemMetricsTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_system_metrics_shape(self):
        response = self.client.get("/api/v1/system/metrics/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("metrics", payload)
        self.assertIn("services", payload)
        self.assertIn("cpu_percent", payload["metrics"])
        self.assertTrue(any(service["name"] == "API Server" for service in payload["services"]))
