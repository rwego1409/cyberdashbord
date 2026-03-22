from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from osint.models import ThreatEvent


class AnalyticsEndpointsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.operator_headers = {"HTTP_X_DEBUG_ROLE": "analyst"}
        now = timezone.now()
        ThreatEvent.objects.create(
            source="manual",
            event_type="malware_activity",
            occurred_at=now,
            country_code="TZ",
            region="Dar es Salaam",
            severity_score=8.2,
        )
        ThreatEvent.objects.create(
            source="nvd",
            event_type="cve_disclosure",
            occurred_at=now - timedelta(hours=2),
            country_code="TZ",
            region="Arusha",
            severity_score=6.1,
        )

    def test_risk_overview_shape(self):
        response = self.client.get("/api/v1/analytics/risk-overview/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("national_risk_index", payload)
        self.assertIn("regional_comparison", payload)
        self.assertIn("top_attack_vectors", payload)
        self.assertGreaterEqual(len(payload["regional_comparison"]), 1)

    def test_snapshot_ingest_and_list(self):
        now = timezone.now().date()
        ingest_response = self.client.post(
            "/api/v1/analytics/snapshots/ingest/",
            {
                "country_code": "TZ",
                "region": "Dar es Salaam",
                "period_start": (now - timedelta(days=7)).isoformat(),
                "period_end": now.isoformat(),
                "attack_volume": 15,
                "malware_volume": 4,
                "exposure_score": 6.9,
                "risk_index": 72.4,
            },
            format="json",
            **self.operator_headers,
        )
        self.assertEqual(ingest_response.status_code, 201)
        self.assertEqual(ingest_response.json()["created_count"], 1)

        list_response = self.client.get("/api/v1/analytics/snapshots/?limit=10")
        self.assertEqual(list_response.status_code, 200)
        self.assertGreaterEqual(len(list_response.json()["snapshots"]), 1)

    def test_snapshot_generate_uses_recent_events(self):
        response = self.client.post(
            "/api/v1/analytics/snapshots/generate/",
            {},
            format="json",
            **self.operator_headers,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("generated", payload)
        self.assertGreaterEqual(payload["generated"], 1)
