from django.db import transaction
from django.utils import timezone

from alerts.models import AlertEvent, AlertRule
from scans.models import ScanFinding, ScanJob


def alert_channel_for_severity(severity: str) -> str:
    if severity == "critical":
        return "telegram"
    if severity == "high":
        return "email"
    return "webhook"


def emit_alert_for_finding(finding: ScanFinding) -> None:
    if finding.severity not in {"critical", "high"}:
        return

    rule, _ = AlertRule.objects.get_or_create(
        name=f"auto-{finding.severity}-finding",
        defaults={
            "scope": "asset",
            "channel": alert_channel_for_severity(finding.severity),
            "threshold": 1.0,
            "enabled": True,
        },
    )

    AlertEvent.objects.create(
        rule=rule,
        severity=finding.severity,
        title=f"{finding.severity.upper()} finding on {finding.scan_job.asset.value}",
        details={
            "scan_job_id": finding.scan_job_id,
            "asset": finding.scan_job.asset.value,
            "scanner_type": finding.scan_job.scanner_type,
            "cve": finding.cve,
            "title": finding.title,
            "port": finding.port,
        },
        status="open",
    )


def synthetic_findings_for_job(job: ScanJob) -> list[dict]:
    asset = job.asset.value
    if job.scanner_type == "openvas":
        return [
            {
                "severity": "high",
                "title": f"Vulnerability exposure detected on {asset}",
                "cve": "CVE-2023-12345",
                "port": 443,
                "protocol": "tcp",
                "recommendation": "Upgrade vulnerable package and apply vendor patch.",
                "reference": "https://nvd.nist.gov",
                "is_patch_available": True,
            }
        ]
    if job.scanner_type == "vulners":
        return [
            {
                "severity": "critical",
                "title": f"Known exploited CVE exposed on {asset}",
                "cve": "CVE-2024-3094",
                "port": 22,
                "protocol": "tcp",
                "recommendation": "Apply emergency patch and restrict access immediately.",
                "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "is_patch_available": True,
            }
        ]
    return [
        {
            "severity": "medium",
            "title": f"Open service risk identified on {asset}",
            "cve": "",
            "port": 3389,
            "protocol": "tcp",
            "recommendation": "Restrict exposed service to trusted networks only.",
            "reference": "",
            "is_patch_available": False,
        }
    ]


def reserve_queued_jobs(limit: int) -> list[ScanJob]:
    now = timezone.now()
    with transaction.atomic():
        jobs = list(
            ScanJob.objects.select_for_update()
            .filter(status="queued")
            .order_by("created_at")[:limit]
        )
        for job in jobs:
            job.status = "running"
            job.started_at = now
            job.save(update_fields=["status", "started_at", "updated_at"])
    return jobs


def process_queued_scan_jobs(limit: int = 5) -> dict:
    jobs = reserve_queued_jobs(limit=limit)
    completed_ids: list[int] = []
    findings_created = 0

    for job in jobs:
        findings_payload = synthetic_findings_for_job(job)
        for finding_payload in findings_payload:
            finding = ScanFinding.objects.create(
                scan_job=job,
                severity=finding_payload["severity"],
                title=finding_payload["title"],
                cve=finding_payload.get("cve", ""),
                port=finding_payload.get("port"),
                protocol=finding_payload.get("protocol", ""),
                recommendation=finding_payload.get("recommendation", ""),
                reference=finding_payload.get("reference", ""),
                is_patch_available=finding_payload.get("is_patch_available", False),
            )
            emit_alert_for_finding(finding)
            findings_created += 1

        job.status = "completed"
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "completed_at", "updated_at"])
        completed_ids.append(job.id)

    return {
        "reserved": len(jobs),
        "completed_job_ids": completed_ids,
        "findings_created": findings_created,
    }
