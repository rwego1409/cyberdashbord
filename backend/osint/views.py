import os

from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from common.permissions import IsOperatorOrDebugRole
from osint.models import ThreatEvent


class ThreatEventIngestSerializer(serializers.Serializer):
    source = serializers.ChoiceField(choices=ThreatEvent.SOURCE_CHOICES)
    event_type = serializers.CharField(max_length=64)
    occurred_at = serializers.DateTimeField()
    country_code = serializers.CharField(max_length=3, required=False, default="TZ")
    region = serializers.CharField(max_length=128, required=False, allow_blank=True)
    district = serializers.CharField(max_length=128, required=False, allow_blank=True)
    ward = serializers.CharField(max_length=128, required=False, allow_blank=True)
    indicator = serializers.CharField(max_length=64, required=False, allow_blank=True)
    value = serializers.CharField(max_length=255, required=False, allow_blank=True)
    severity_score = serializers.FloatField(required=False, default=0.0)
    raw_payload = serializers.JSONField(required=False, default=dict)


class ThreatEventIngestView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        is_many = isinstance(request.data, list)
        serializer = ThreatEventIngestSerializer(data=request.data, many=is_many)
        serializer.is_valid(raise_exception=True)
        records = serializer.validated_data

        created = []
        iterable = records if is_many else [records]
        for item in iterable:
            event = ThreatEvent.objects.create(**item)
            created.append(event.id)

        return Response({"created_count": len(created), "event_ids": created}, status=status.HTTP_201_CREATED)


class OsintSummaryView(APIView):
    def get(self, request):
        source_counts = {
            source: ThreatEvent.objects.filter(source=source).count()
            for source, _ in ThreatEvent.SOURCE_CHOICES
        }
        top_regions = (
            ThreatEvent.objects.exclude(region="")
            .values("country_code", "region")
            .order_by("country_code", "region")
            .distinct()[:10]
        )

        return Response(
            {
                "feeds": source_counts,
                "regional_coverage": list(top_regions),
                "total_events": ThreatEvent.objects.count(),
                "status": "collector module live",
            }
        )


class SourceHealthView(APIView):
    def get(self, request):
        source_counts = {
            source: ThreatEvent.objects.filter(source=source).count()
            for source, _ in ThreatEvent.SOURCE_CHOICES
        }
        required_env = {
            "tzcert": [],
            "nvd": [],
            "abuseipdb": ["ABUSEIPDB_API_KEY"],
            "otx": ["OTX_API_KEY"],
            "acled": ["ACLED_API_KEY", "ACLED_EMAIL"],
            "manual": [],
        }

        sources = []
        for source, _label in ThreatEvent.SOURCE_CHOICES:
            env_names = required_env.get(source, [])
            missing = [name for name in env_names if not os.getenv(name, "").strip()]
            configured = len(missing) == 0
            count = source_counts.get(source, 0)
            if count > 0:
                status_label = "active"
            elif configured:
                status_label = "configured_no_data"
            else:
                status_label = "missing_config"

            sources.append(
                {
                    "source": source,
                    "events": count,
                    "configured": configured,
                    "required_env": env_names,
                    "missing_env": missing,
                    "status": status_label,
                }
            )

        return Response(
            {
                "sources": sources,
                "total_events": sum(source_counts.values()),
                "status": "ok",
            }
        )


class ThreatEventListView(APIView):
    def get(self, request):
        try:
            limit = max(1, min(200, int(request.query_params.get("limit", 100))))
        except ValueError:
            limit = 100
        events = ThreatEvent.objects.order_by("-occurred_at").values(
            "id",
            "source",
            "event_type",
            "occurred_at",
            "country_code",
            "region",
            "district",
            "ward",
            "indicator",
            "value",
            "severity_score",
        )[:limit]
        return Response({"events": list(events)})
