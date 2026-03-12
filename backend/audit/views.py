from rest_framework.response import Response
from rest_framework.views import APIView

from audit.models import AuditLog


class AuditLogListView(APIView):
    def get(self, request):
        try:
            limit = max(1, min(200, int(request.query_params.get("limit", 100))))
        except ValueError:
            limit = 100

        logs = AuditLog.objects.order_by("-created_at").values(
            "id",
            "actor",
            "action",
            "target_type",
            "target_id",
            "outcome",
            "metadata",
            "created_at",
        )[:limit]
        return Response({"logs": list(logs)})

