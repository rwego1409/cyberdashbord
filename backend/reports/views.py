import csv
from io import BytesIO, StringIO

from django.http import HttpResponse
from django.utils import timezone
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from rest_framework.response import Response
from rest_framework.views import APIView

from common.permissions import IsOperatorOrDebugRole
from reports.services import (
    append_immutable_export_record,
    canonical_json_bytes,
    list_export_ledger,
    parse_bool,
    sha256_hex,
    sign_hash,
    verify_export_ledger,
)
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
        signed = parse_bool(request.query_params.get("signed"), default=False)
        immutable = parse_bool(request.query_params.get("immutable"), default=False)
        if immutable:
            signed = True

        if report_type == "scan":
            payload = _scan_report_payload()
        elif report_type == "regional":
            payload = _regional_report_payload()
        elif report_type == "national":
            payload = _national_report_payload()
        else:
            return Response({"detail": "Unsupported report type"}, status=400)

        artifact_bytes: bytes
        content_type = "application/octet-stream"
        file_name = f"{report_type}-report"
        file_extension = export_format

        if export_format == "json":
            artifact_bytes = canonical_json_bytes(payload)
            content_type = "application/json"
            file_name = f"{file_name}.json"
        elif export_format == "csv":
            csv_content = _to_csv(report_type, payload)
            artifact_bytes = csv_content.encode("utf-8")
            content_type = "text/csv"
            file_name = f"{file_name}.csv"
        elif export_format == "pdf":
            artifact_bytes = _to_pdf(report_type, payload)
            content_type = "application/pdf"
            file_name = f"{file_name}.pdf"
        else:
            return Response({"detail": "Unsupported export format"}, status=400)

        signature_meta = None
        if signed:
            digest = sha256_hex(artifact_bytes)
            signature = sign_hash(digest)
            signature_meta = {
                "sha256": digest,
                "algorithm": "hmac-sha256",
                "signature": signature,
                "immutable": immutable,
            }
            if immutable:
                ledger_entry = append_immutable_export_record(
                    report_type=report_type,
                    export_format=export_format,
                    artifact_bytes=artifact_bytes,
                    artifact_extension=file_extension,
                    artifact_hash=digest,
                    signature=signature,
                )
                signature_meta["ledger_entry_id"] = ledger_entry["id"]
                signature_meta["chain_hash"] = ledger_entry["chain_hash"]

        if export_format == "json":
            if not signature_meta:
                return Response(payload)
            response = Response({"report": payload, "signature": signature_meta})
        else:
            response = HttpResponse(artifact_bytes, content_type=content_type)
            response["Content-Disposition"] = f'attachment; filename="{file_name}"'

        if signature_meta:
            response["X-Report-SHA256"] = signature_meta["sha256"]
            response["X-Report-Signature"] = signature_meta["signature"]
            if signature_meta.get("ledger_entry_id"):
                response["X-Report-Ledger-Entry"] = signature_meta["ledger_entry_id"]

        return response


class ReportExportLedgerView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def get(self, request):
        try:
            limit = max(1, min(200, int(request.query_params.get("limit", 50))))
        except ValueError:
            limit = 50

        entries = list_export_ledger(limit=limit)
        integrity = verify_export_ledger(limit=limit)
        return Response(
            {
                "count": len(entries),
                "entries": entries,
                "integrity": integrity,
            }
        )
