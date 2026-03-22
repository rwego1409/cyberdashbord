from django.test import TestCase
from rest_framework.test import APIClient

from audit.models import AuditLog


class AuditLogEndpointsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        AuditLog.objects.create(
            actor="system",
            action="seed",
            target_type="bootstrap",
            target_id="1",
            outcome="success",
            metadata={"channel": "tests"},
        )
        AuditLog.objects.create(
            actor="analyst",
            action="scan_job_create",
            target_type="scan_job",
            target_id="22",
            outcome="failure",
            metadata={"reason": "consent_expired"},
        )

    def test_audit_logs_list_and_limit(self):
        response = self.client.get("/api/v1/audit/logs/?limit=1")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("logs", payload)
        self.assertEqual(len(payload["logs"]), 1)
        self.assertEqual(payload["logs"][0]["action"], "scan_job_create")
