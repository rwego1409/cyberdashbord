from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.models import AlertEvent
from alerts.services import dispatch_open_alerts
from common.permissions import IsOperatorOrDebugRole


class DispatchSerializer(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=100, default=20)


class ActiveAlertsView(APIView):
    def get(self, request):
        active = (
            AlertEvent.objects.filter(status="open")
            .order_by("-created_at")
            .values("id", "severity", "title", "status", "details", "created_at")[:50]
        )

        return Response(
            {
                "active": list(active),
                "channels": ["email", "telegram", "webhook"],
                "open_count": AlertEvent.objects.filter(status="open").count(),
                "status": "notification module live",
            }
        )


class DispatchAlertsView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = DispatchSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        limit = serializer.validated_data["limit"]
        return Response(dispatch_open_alerts(limit=limit))


class AcknowledgeAlertView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request, alert_id: int):
        alert = AlertEvent.objects.filter(id=alert_id).first()
        if not alert:
            return Response({"detail": "Alert not found"}, status=404)
        alert.status = "acknowledged"
        alert.save(update_fields=["status"])
        return Response({"alert_id": alert.id, "status": alert.status})
