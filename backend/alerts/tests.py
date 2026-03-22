from django.test import TestCase
from rest_framework.test import APIClient

from alerts.models import AlertEvent, AlertRule


class AlertsEndpointsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.operator_headers = {"HTTP_X_DEBUG_ROLE": "analyst"}
        self.rule = AlertRule.objects.create(
            name="high-risk-rule",
            scope="asset",
            channel="email",
            threshold=1.0,
            enabled=True,
        )
        self.alert = AlertEvent.objects.create(
            rule=self.rule,
            severity="high",
            title="High severity test alert",
            details={"origin": "tests"},
            status="open",
        )

    def test_active_alerts_lists_open_alerts(self):
        response = self.client.get("/api/v1/alerts/active/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["open_count"], 1)
        self.assertEqual(len(payload["active"]), 1)
        self.assertEqual(payload["active"][0]["id"], self.alert.id)

    def test_dispatch_updates_alert_details(self):
        response = self.client.post(
            "/api/v1/alerts/dispatch/",
            {"limit": 10},
            format="json",
            **self.operator_headers,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["dispatched_count"], 1)

        self.alert.refresh_from_db()
        self.assertIn("last_dispatched_at", self.alert.details)
        self.assertEqual(self.alert.details["dispatch_channel"], "email")

    def test_acknowledge_alert_marks_alert_acknowledged(self):
        response = self.client.post(
            f"/api/v1/alerts/{self.alert.id}/ack/",
            {},
            format="json",
            **self.operator_headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "acknowledged")

        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, "acknowledged")
