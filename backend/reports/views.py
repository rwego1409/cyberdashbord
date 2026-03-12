import csv
from io import BytesIO, StringIO

from django.http import HttpResponse
from django.utils import timezone
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.models import AlertEvent
from analytics.models import RegionalRiskSnapshot
from osint.models import ThreatEvent
from scans.models import ScanFinding, ScanJob


def _scan_report_payload() -> dict:
    findings_by_severity = {}
    for severity, _label in ScanFinding.SEVERITY_CHOICES:
        findings_by_severity[severity] = ScanFinding.objects.filter(severity=severity).count()

    top_ports = (
        ScanFinding.objects.exclude(port__isnull=True)
        .values("port")
        .order_by("port")
    )
    port_counts: dict[int, int] = {}
    for row in top_ports:
        port = int(row["port"])
        port_counts[port] = port_counts.get(port, 0) + 1

    return {
        "generated_at": timezone.now().isoformat(),
        "jobs": {
            "queued": ScanJob.objects.filter(status="queued").count(),
            "running": ScanJob.objects.filter(status="running").count(),
            "completed": ScanJob.objects.filter(status="completed").count(),
            "failed": ScanJob.objects.filter(status="failed").count(),
        },
        "total_findings": ScanFinding.objects.count(),
        "findings_by_severity": findings_by_severity,
        "top_ports": [
            {"port": port, "count": count}
            for port, count in sorted(port_counts.items(), key=lambda item: item[1], reverse=True)[:10]
        ],
    }


def _regional_report_payload() -> dict:
    snapshots = list(
        RegionalRiskSnapshot.objects.order_by("-generated_at").values(
            "country_code",
            "region",
            "risk_index",
            "attack_volume",
            "malware_volume",
            "generated_at",
        )[:30]
    )
    return {
        "generated_at": timezone.now().isoformat(),
        "snapshot_count": len(snapshots),
        "regions": snapshots,
    }


def _national_report_payload() -> dict:
    total_events = ThreatEvent.objects.count()
    avg_severity = (
        sum(row.severity_score for row in ThreatEvent.objects.all()[:1000]) / total_events
        if total_events
        else 0.0
    )
    open_alerts = AlertEvent.objects.filter(status="open").count()
    critical_findings = ScanFinding.objects.filter(severity="critical").count()
    high_findings = ScanFinding.objects.filter(severity="high").count()

    national_risk_index = round((avg_severity * 10) + (critical_findings * 10) + (high_findings * 5) + (open_alerts * 3), 2)
    return {
        "generated_at": timezone.now().isoformat(),
        "total_events": total_events,
        "open_alerts": open_alerts,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "national_risk_index": national_risk_index,
    }


def _all_reports_payload() -> dict:
    return {
        "scan_report": _scan_report_payload(),
        "regional_report": _regional_report_payload(),
        "national_report": _national_report_payload(),
    }


def _to_csv(report_type: str, payload: dict) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["report_type", report_type])
    for key, value in payload.items():
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                writer.writerow([f"{key}.{child_key}", child_value])
        elif isinstance(value, list):
            writer.writerow([key, "items"])
            if value and isinstance(value[0], dict):
                header = sorted({k for item in value for k in item.keys()})
                writer.writerow(header)
                for item in value:
                    writer.writerow([item.get(h, "") for h in header])
            else:
                for item in value:
                    writer.writerow([item])
        else:
            writer.writerow([key, value])
    return output.getvalue()


def _to_pdf(report_type: str, payload: dict) -> bytes:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 40
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(40, y, f"TCIO {report_type.replace('_', ' ').title()} Report")
    y -= 24
    pdf.setFont("Helvetica", 10)

    lines: list[str] = []
    for key, value in payload.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for child_key, child_value in value.items():
                lines.append(f"  {child_key}: {child_value}")
        elif isinstance(value, list):
            lines.append(f"{key}: {len(value)} item(s)")
            for item in value[:10]:
                lines.append(f"  - {item}")
        else:
            lines.append(f"{key}: {value}")

    for line in lines:
        if y < 50:
            pdf.showPage()
            y = height - 40
            pdf.setFont("Helvetica", 10)
        pdf.drawString(40, y, line[:120])
        y -= 14

    pdf.save()
    return buffer.getvalue()


class ReportsSummaryView(APIView):
    def get(self, request):
        return Response(_all_reports_payload())


class ReportExportView(APIView):
    def get(self, request):
        report_type = request.query_params.get("type", "scan")
        export_format = request.query_params.get("format", "json")

        if report_type == "scan":
            payload = _scan_report_payload()
        elif report_type == "regional":
            payload = _regional_report_payload()
        elif report_type == "national":
            payload = _national_report_payload()
        else:
            return Response({"detail": "Unsupported report type"}, status=400)

        if export_format == "json":
            return Response(payload)
        if export_format == "csv":
            csv_content = _to_csv(report_type, payload)
            response = HttpResponse(csv_content, content_type="text/csv")
            response["Content-Disposition"] = f'attachment; filename="{report_type}-report.csv"'
            return response
        if export_format == "pdf":
            pdf_content = _to_pdf(report_type, payload)
            response = HttpResponse(pdf_content, content_type="application/pdf")
            response["Content-Disposition"] = f'attachment; filename="{report_type}-report.pdf"'
            return response

        return Response({"detail": "Unsupported export format"}, status=400)
