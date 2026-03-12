import os
import time
from datetime import datetime, timezone

from django.db import connection
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.models import AlertEvent
from analytics.models import RegionalRiskSnapshot
from osint.models import ThreatEvent
from scans.models import ScanJob

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class HealthView(APIView):
    def get(self, request):
        return Response(
            {
                "service": "tcio-backend",
                "status": "ok",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            }
        )


def _service_status(last_seen: datetime | None, threshold_minutes: int = 120) -> str:
    if not last_seen:
        return "offline"
    age_minutes = (datetime.now(timezone.utc) - last_seen).total_seconds() / 60
    if age_minutes <= threshold_minutes:
        return "healthy"
    if age_minutes <= threshold_minutes * 6:
        return "degraded"
    return "offline"


class SystemMetricsView(APIView):
    def get(self, request):
        cpu_percent = psutil.cpu_percent(interval=0.1) if psutil else 0.0
        memory_percent = psutil.virtual_memory().percent if psutil else 0.0
        network_sent = 0
        network_recv = 0
        if psutil:
            net = psutil.net_io_counters()
            network_sent = net.bytes_sent
            network_recv = net.bytes_recv

        load_avg = [0.0, 0.0, 0.0]
        if hasattr(os, "getloadavg"):
            load_avg = list(os.getloadavg())

        db_start = time.perf_counter()
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        db_latency_ms = round((time.perf_counter() - db_start) * 1000, 2)

        latest_event = ThreatEvent.objects.order_by("-created_at").values_list("created_at", flat=True).first()
        latest_scan = ScanJob.objects.order_by("-updated_at").values_list("updated_at", flat=True).first()
        latest_snapshot = RegionalRiskSnapshot.objects.order_by("-generated_at").values_list("generated_at", flat=True).first()
        latest_alert = AlertEvent.objects.order_by("-created_at").values_list("created_at", flat=True).first()

        services = [
            {
                "name": "API Server",
                "status": "healthy",
                "last_seen": datetime.now(timezone.utc),
                "details": "Serving backend API routes.",
            },
            {
                "name": "Database",
                "status": "healthy" if db_latency_ms < 500 else "degraded",
                "last_seen": datetime.now(timezone.utc),
                "details": f"Database ping latency: {db_latency_ms} ms",
            },
            {
                "name": "Scrapers",
                "status": _service_status(latest_event),
                "last_seen": latest_event,
                "details": "Based on most recent OSINT event ingestion time.",
            },
            {
                "name": "Scanner Orchestrator",
                "status": _service_status(latest_scan),
                "last_seen": latest_scan,
                "details": "Based on most recent scan job update.",
            },
            {
                "name": "AI Analytics Engine",
                "status": _service_status(latest_snapshot),
                "last_seen": latest_snapshot,
                "details": "Based on latest risk snapshot generation.",
            },
            {
                "name": "Automation",
                "status": _service_status(latest_alert),
                "last_seen": latest_alert,
                "details": "Based on latest alert lifecycle event.",
            },
        ]

        return Response(
            {
                "metrics": {
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(memory_percent, 2),
                    "network_bytes_sent": network_sent,
                    "network_bytes_recv": network_recv,
                    "load_avg": load_avg,
                    "db_latency_ms": db_latency_ms,
                },
                "services": services,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            }
        )
