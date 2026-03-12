import ipaddress
from fnmatch import fnmatch
from uuid import UUID

from django.db.models import Count
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.models import AuditLog
from common.permissions import IsOperatorOrDebugRole
from consent.models import ConsentGrant
from scans.models import Asset, ScanFinding, ScanJob
from scans.services import emit_alert_for_finding, process_queued_scan_jobs, reserve_queued_jobs
from scans.tasks import process_queued_scan_jobs_task


class ScanJobCreateSerializer(serializers.Serializer):
    consent_id = serializers.CharField()
    asset_type = serializers.ChoiceField(choices=Asset.TYPE_CHOICES)
    asset_value = serializers.CharField(max_length=255)
    asset_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    scanner_type = serializers.ChoiceField(choices=ScanJob.SCANNER_CHOICES)
    requested_by = serializers.CharField(max_length=150, required=False, allow_blank=True)
    metadata = serializers.JSONField(required=False)


class ScanJobReserveSerializer(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=50, default=5)


class ScanFindingInputSerializer(serializers.Serializer):
    severity = serializers.ChoiceField(choices=ScanFinding.SEVERITY_CHOICES)
    title = serializers.CharField(max_length=255)
    cve = serializers.CharField(max_length=32, required=False, allow_blank=True)
    port = serializers.IntegerField(required=False, min_value=1, max_value=65535)
    protocol = serializers.CharField(max_length=16, required=False, allow_blank=True)
    recommendation = serializers.CharField(required=False, allow_blank=True)
    reference = serializers.URLField(required=False, allow_blank=True)
    is_patch_available = serializers.BooleanField(default=False)


class ScanJobCompleteSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["completed", "failed"], default="completed")
    findings = ScanFindingInputSerializer(many=True, required=False)
    metadata = serializers.JSONField(required=False)


class ScanProcessOnceSerializer(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=20, default=5)


class ScanProcessAsyncSerializer(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=100, default=20)


PROGRESS_STAGES = [
    "target_validation",
    "port_discovery",
    "service_detection",
    "vulnerability_detection",
    "ai_risk_scoring",
]


def _progress_for_status(status_value: str) -> dict:
    if status_value == "queued":
        current = "target_validation"
    elif status_value == "running":
        current = "vulnerability_detection"
    elif status_value == "completed":
        current = "ai_risk_scoring"
    else:
        current = None

    stage_rows = []
    current_index = PROGRESS_STAGES.index(current) if current in PROGRESS_STAGES else -1
    for index, stage in enumerate(PROGRESS_STAGES):
        stage_status = "pending"
        if status_value == "completed":
            stage_status = "completed"
        elif status_value == "failed" and index <= 2:
            stage_status = "completed"
        elif current_index == index:
            stage_status = "current"
        elif current_index > index:
            stage_status = "completed"
        stage_rows.append({"stage": stage, "status": stage_status})

    return {
        "current_stage": current if status_value in {"queued", "running"} else (
            "completed" if status_value == "completed" else "failed"
        ),
        "stages": stage_rows,
    }


def _is_consent_valid_for_target(target_pattern: str, target_value: str) -> bool:
    if target_pattern == "*" or target_pattern == target_value:
        return True
    if "*" in target_pattern and fnmatch(target_value, target_pattern):
        return True
    try:
        network = ipaddress.ip_network(target_pattern, strict=False)
        ip = ipaddress.ip_address(target_value)
        return ip in network
    except ValueError:
        return False


class ScanJobCreateView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = ScanJobCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data

        try:
            parsed_uuid = UUID(str(payload["consent_id"]))
        except ValueError:
            return Response({"detail": "Invalid consent_id format"}, status=status.HTTP_400_BAD_REQUEST)

        consent = ConsentGrant.objects.filter(consent_id=parsed_uuid).first()
        if not consent:
            return Response({"detail": "Consent not found"}, status=status.HTTP_404_NOT_FOUND)

        now = timezone.now()
        if consent.status != "active" or consent.valid_until < now:
            AuditLog.objects.create(
                actor=payload.get("requested_by", ""),
                action="scan_job_create",
                target_type="consent",
                target_id=str(consent.consent_id),
                outcome="failure",
                metadata={"reason": "consent_inactive_or_expired"},
            )
            return Response({"detail": "Consent is inactive or expired"}, status=status.HTTP_403_FORBIDDEN)

        if consent.allowed_scanners and payload["scanner_type"] not in consent.allowed_scanners:
            return Response({"detail": "Scanner type not allowed by consent"}, status=status.HTTP_403_FORBIDDEN)

        if not _is_consent_valid_for_target(consent.target, payload["asset_value"]):
            return Response({"detail": "Target is outside authorized consent scope"}, status=status.HTTP_403_FORBIDDEN)

        asset, _ = Asset.objects.get_or_create(
            organization=consent.organization,
            asset_type=payload["asset_type"],
            value=payload["asset_value"],
            defaults={"name": payload.get("asset_name", "")},
        )

        job = ScanJob.objects.create(
            asset=asset,
            consent=consent,
            scanner_type=payload["scanner_type"],
            requested_by=payload.get("requested_by", ""),
            metadata=payload.get("metadata", {}),
            status="queued",
        )

        AuditLog.objects.create(
            actor=payload.get("requested_by", ""),
            action="scan_job_create",
            target_type="scan_job",
            target_id=str(job.id),
            outcome="success",
            metadata={"scanner": job.scanner_type, "asset": asset.value},
        )

        return Response(
            {
                "scan_job_id": job.id,
                "status": job.status,
                "scanner_type": job.scanner_type,
                "asset": {"type": asset.asset_type, "value": asset.value},
                "consent_id": str(consent.consent_id),
            },
            status=status.HTTP_201_CREATED,
        )


class ScanJobListView(APIView):
    def get(self, request):
        try:
            limit = max(1, min(100, int(request.query_params.get("limit", 30))))
        except ValueError:
            limit = 30

        jobs = (
            ScanJob.objects.select_related("asset", "consent")
            .annotate(findings_count=Count("findings"))
            .order_by("-created_at")[:limit]
        )

        payload = [
            {
                "id": job.id,
                "status": job.status,
                "scanner_type": job.scanner_type,
                "asset": {"type": job.asset.asset_type, "value": job.asset.value},
                "consent_id": str(job.consent.consent_id),
                "requested_by": job.requested_by,
                "findings_count": job.findings_count,
                "created_at": job.created_at,
                "started_at": job.started_at,
                "completed_at": job.completed_at,
            }
            for job in jobs
        ]
        return Response({"jobs": payload})


class ScanFindingListView(APIView):
    def get(self, request):
        try:
            limit = max(1, min(300, int(request.query_params.get("limit", 100))))
        except ValueError:
            limit = 100

        findings_qs = (
            ScanFinding.objects.select_related("scan_job", "scan_job__asset")
            .order_by("-created_at")[:limit]
        )
        findings = [
            {
                "id": finding.id,
                "scan_job_id": finding.scan_job_id,
                "asset": finding.scan_job.asset.value,
                "scanner_type": finding.scan_job.scanner_type,
                "severity": finding.severity,
                "title": finding.title,
                "cve": finding.cve,
                "port": finding.port,
                "protocol": finding.protocol,
                "recommendation": finding.recommendation,
                "reference": finding.reference,
                "is_patch_available": finding.is_patch_available,
                "created_at": finding.created_at,
            }
            for finding in findings_qs
        ]

        severity_distribution = {
            row["severity"]: row["count"]
            for row in ScanFinding.objects.values("severity").annotate(count=Count("id"))
        }

        port_rows = (
            ScanFinding.objects.exclude(port__isnull=True)
            .values("port")
            .annotate(count=Count("id"))
            .order_by("-count")[:15]
        )
        open_ports = [{"port": row["port"], "count": row["count"]} for row in port_rows]

        return Response(
            {
                "findings": findings,
                "severity_distribution": severity_distribution,
                "open_ports": open_ports,
                "count": len(findings),
            }
        )


class ScanJobProgressView(APIView):
    def get(self, request, job_id: int):
        job = ScanJob.objects.select_related("asset").filter(id=job_id).first()
        if not job:
            return Response({"detail": "Scan job not found"}, status=status.HTTP_404_NOT_FOUND)

        progress = _progress_for_status(job.status)
        return Response(
            {
                "scan_job_id": job.id,
                "status": job.status,
                "scanner_type": job.scanner_type,
                "asset": {"type": job.asset.asset_type, "value": job.asset.value},
                "progress": progress,
                "timestamps": {
                    "created_at": job.created_at,
                    "started_at": job.started_at,
                    "completed_at": job.completed_at,
                },
            }
        )


class ScanJobReserveView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = ScanJobReserveSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        limit = serializer.validated_data["limit"]
        jobs = reserve_queued_jobs(limit=limit)

        return Response(
            {
                "reserved": len(jobs),
                "jobs": [
                    {
                        "id": job.id,
                        "scanner_type": job.scanner_type,
                        "asset": {"type": job.asset.asset_type, "value": job.asset.value},
                        "requested_by": job.requested_by,
                        "metadata": job.metadata,
                    }
                    for job in jobs
                ],
            }
        )


class ScanJobCompleteView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request, job_id: int):
        job = ScanJob.objects.select_related("asset").filter(id=job_id).first()
        if not job:
            return Response({"detail": "Scan job not found"}, status=status.HTTP_404_NOT_FOUND)
        if job.status == "completed":
            return Response({"detail": "Scan job already completed"}, status=status.HTTP_409_CONFLICT)

        serializer = ScanJobCompleteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data

        findings_created = 0
        if payload["status"] == "completed":
            for finding_payload in payload.get("findings", []):
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

        if payload.get("metadata"):
            merged = dict(job.metadata or {})
            merged.update(payload["metadata"])
            job.metadata = merged

        job.status = payload["status"]
        job.completed_at = timezone.now()
        if not job.started_at:
            job.started_at = job.completed_at
        job.save(update_fields=["status", "metadata", "completed_at", "started_at", "updated_at"])

        AuditLog.objects.create(
            actor="scanner-orchestrator",
            action="scan_job_complete",
            target_type="scan_job",
            target_id=str(job.id),
            outcome="success" if job.status == "completed" else "failure",
            metadata={"findings_created": findings_created, "status": job.status},
        )

        return Response(
            {
                "scan_job_id": job.id,
                "status": job.status,
                "findings_created": findings_created,
            }
        )


class ScanSummaryView(APIView):
    def get(self, request):
        queued = ScanJob.objects.filter(status="queued").count()
        running = ScanJob.objects.filter(status="running").count()
        completed = ScanJob.objects.filter(status="completed").count()
        failed = ScanJob.objects.filter(status="failed").count()
        findings_count = ScanFinding.objects.count()
        top_assets = Asset.objects.all().order_by("-updated_at").values("asset_type", "value")[:5]
        return Response(
            {
                "authorization_mode": "consent-gated",
                "supported_scanners": ["nmap", "openvas", "vulners"],
                "jobs": {
                    "queued": queued,
                    "running": running,
                    "completed": completed,
                    "failed": failed,
                },
                "findings_count": findings_count,
                "recent_assets": list(top_assets),
            }
        )


class ScanProcessOnceView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = ScanProcessOnceSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        limit = serializer.validated_data["limit"]
        return Response(process_queued_scan_jobs(limit=limit))


class ScanProcessAsyncView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = ScanProcessAsyncSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        limit = serializer.validated_data["limit"]
        task = process_queued_scan_jobs_task.delay(limit=limit)
        return Response({"task_id": task.id, "status": "queued", "limit": limit}, status=status.HTTP_202_ACCEPTED)
