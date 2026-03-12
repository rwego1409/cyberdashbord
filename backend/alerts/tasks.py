from celery import shared_task

from alerts.services import dispatch_open_alerts


@shared_task(name="alerts.dispatch_open_alerts")
def dispatch_open_alerts_task(limit: int = 20) -> dict:
    return dispatch_open_alerts(limit=limit)
