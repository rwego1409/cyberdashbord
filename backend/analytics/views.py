from django.db.models import Avg, Count, Q
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.models import AlertEvent
from analytics.models import RegionalRiskSnapshot
from analytics.services import generate_regional_snapshots
from common.permissions import IsOperatorOrDebugRole
from osint.models import ThreatEvent
from scans.models import ScanFinding


class SnapshotIngestSerializer(serializers.Serializer):
    country_code = serializers.CharField(max_length=3, default="TZ")
    region = serializers.CharField(max_length=128, required=False, allow_blank=True)
    period_start = serializers.DateField()
    period_end = serializers.DateField()
    attack_volume = serializers.IntegerField(min_value=0, default=0)
    malware_volume = serializers.IntegerField(min_value=0, default=0)
    exposure_score = serializers.FloatField(default=0.0)
    risk_index = serializers.FloatField(default=0.0)


class RiskOverviewView(APIView):
    def get(self, request):
        total_events = ThreatEvent.objects.count()
        avg_severity = ThreatEvent.objects.aggregate(avg=Avg("severity_score"))["avg"] or 0.0

        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        findings_by_severity = dict(ScanFinding.objects.values_list("severity").annotate(count=Count("id")))
        weighted_findings = sum(severity_weights.get(k, 1) * v for k, v in findings_by_severity.items())

        open_alerts = AlertEvent.objects.filter(status="open").count()
        national_risk_index = round((avg_severity * 10) + weighted_findings + (open_alerts * 5), 2)

        top_attack_vectors = (
            ThreatEvent.objects.values("event_type")
            .annotate(count=Count("id"))
            .order_by("-count")[:8]
        )

        regional = (
            ThreatEvent.objects.exclude(region="")
            .values("country_code", "region")
            .annotate(
                events=Count("id"),
                avg_severity=Avg("severity_score"),
                critical_events=Count("id", filter=Q(severity_score__gte=8)),
            )
            .order_by("-events")[:25]
        )

        latest_snapshots = RegionalRiskSnapshot.objects.order_by("-generated_at").values(
            "country_code", "region", "risk_index", "period_start", "period_end"
        )[:10]

        return Response(
            {
                "national_risk_index": national_risk_index,
                "open_alerts": open_alerts,
                "total_events": total_events,
                "top_attack_vectors": list(top_attack_vectors),
                "regional_comparison": list(regional),
                "latest_snapshots": list(latest_snapshots),
            }
        )


class SnapshotIngestView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        many = isinstance(request.data, list)
        serializer = SnapshotIngestSerializer(data=request.data, many=many)
        serializer.is_valid(raise_exception=True)
        rows = serializer.validated_data if many else [serializer.validated_data]

        created_ids = []
        for row in rows:
            snapshot = RegionalRiskSnapshot.objects.create(**row)
            created_ids.append(snapshot.id)

        return Response({"created_count": len(created_ids), "snapshot_ids": created_ids}, status=status.HTTP_201_CREATED)


class SnapshotListView(APIView):
    def get(self, request):
        try:
            limit = max(1, min(100, int(request.query_params.get("limit", 50))))
        except ValueError:
            limit = 50

        snapshots = RegionalRiskSnapshot.objects.order_by("-generated_at").values(
            "id",
            "country_code",
            "region",
            "period_start",
            "period_end",
            "attack_volume",
            "malware_volume",
            "exposure_score",
            "risk_index",
            "generated_at",
        )[:limit]
        return Response({"snapshots": list(snapshots)})


class SnapshotGenerateView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        return Response(generate_regional_snapshots(days=30))
