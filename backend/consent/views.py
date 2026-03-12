from datetime import timedelta

from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from common.permissions import IsOperatorOrDebugRole
from consent.models import ConsentGrant


class ConsentGrantCreateSerializer(serializers.Serializer):
    requester_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    requester_email = serializers.EmailField(required=False, allow_blank=True)
    target = serializers.CharField(max_length=255)
    allowed_scanners = serializers.ListField(child=serializers.CharField(max_length=20), required=False)
    source = serializers.ChoiceField(choices=ConsentGrant.SOURCE_CHOICES, default="manual")
    blockchain_tx_hash = serializers.CharField(max_length=128, required=False, allow_blank=True)
    valid_from = serializers.DateTimeField(required=False)
    valid_until = serializers.DateTimeField()

    def validate(self, attrs):
        valid_from = attrs.get("valid_from", timezone.now())
        if attrs["valid_until"] <= valid_from:
            raise serializers.ValidationError("valid_until must be greater than valid_from")
        return attrs


class ConsentGrantCreateView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = ConsentGrantCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data

        consent = ConsentGrant.objects.create(
            requester_name=payload.get("requester_name", ""),
            requester_email=payload.get("requester_email", ""),
            target=payload["target"],
            allowed_scanners=payload.get("allowed_scanners", []),
            source=payload.get("source", "manual"),
            blockchain_tx_hash=payload.get("blockchain_tx_hash", ""),
            valid_from=payload.get("valid_from", timezone.now()),
            valid_until=payload["valid_until"],
        )

        return Response(
            {
                "consent_id": str(consent.consent_id),
                "target": consent.target,
                "status": consent.status,
                "valid_until": consent.valid_until,
            },
            status=status.HTTP_201_CREATED,
        )


class ConsentStatusView(APIView):
    def get(self, request):
        now = timezone.now()
        expired = ConsentGrant.objects.filter(status="active", valid_until__lt=now)
        expired.update(status="expired")

        active_count = ConsentGrant.objects.filter(status="active", valid_until__gte=now).count()
        expiring_soon = ConsentGrant.objects.filter(
            status="active",
            valid_until__gte=now,
            valid_until__lte=now + timedelta(days=7),
        ).count()

        latest = ConsentGrant.objects.order_by("-created_at").values(
            "consent_id", "target", "status", "valid_until", "source"
        )[:5]

        return Response(
            {
                "contract_provider": "evm-compatible",
                "consent_enforcement": "enabled",
                "active_consents": active_count,
                "expiring_within_7_days": expiring_soon,
                "recent": list(latest),
            }
        )


class ConsentGrantListView(APIView):
    def get(self, request):
        try:
            limit = max(1, min(200, int(request.query_params.get("limit", 50))))
        except ValueError:
            limit = 50
        grants = ConsentGrant.objects.order_by("-created_at").values(
            "consent_id",
            "target",
            "status",
            "source",
            "blockchain_tx_hash",
            "valid_from",
            "valid_until",
            "created_at",
        )[:limit]
        return Response({"grants": list(grants)})
