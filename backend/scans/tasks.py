from celery import shared_task

from scans.services import process_queued_scan_jobs


@shared_task(name="scans.process_queued_scan_jobs")
def process_queued_scan_jobs_task(limit: int = 20) -> dict:
    return process_queued_scan_jobs(limit=limit)
