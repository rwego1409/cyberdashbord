from django.test import TestCase
from rest_framework.test import APIClient


class ReportsEndpointsTests(TestCase):
    def setUp(self):
        self.client = APIClient()

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
