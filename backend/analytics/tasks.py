from celery import shared_task

from analytics.services import generate_regional_snapshots


@shared_task(name="analytics.generate_regional_snapshots")
def generate_regional_snapshots_task(days: int = 30) -> dict:
    return generate_regional_snapshots(days=days)
