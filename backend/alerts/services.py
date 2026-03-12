from django.utils import timezone

from alerts.models import AlertEvent


def dispatch_open_alerts(limit: int = 20) -> dict:
    open_alerts = list(AlertEvent.objects.filter(status="open").order_by("-created_at")[:limit])
    dispatched = []
    for alert in open_alerts:
        details = dict(alert.details or {})
        details["last_dispatched_at"] = timezone.now().isoformat()
        details["dispatch_channel"] = "telegram" if alert.severity == "critical" else "email"
        alert.details = details
        alert.save(update_fields=["details"])
        dispatched.append({"id": alert.id, "severity": alert.severity, "channel": details["dispatch_channel"]})
    return {"dispatched_count": len(dispatched), "dispatched": dispatched}
