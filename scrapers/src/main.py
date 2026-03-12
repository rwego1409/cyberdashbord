import json
import os
from pathlib import Path
from time import sleep

import requests

from collectors import (
    collect_abuseipdb_events,
    collect_acled_events,
    collect_nvd_events,
    collect_otx_events,
    collect_tzcert_events,
)
from pipelines.normalize import normalize_events


def _safe_collect(name: str, collector) -> tuple[str, list[dict], str | None]:
    try:
        data = collector()
        return name, data, None
    except Exception as exc:  # noqa: BLE001
        return name, [], str(exc)


def _collect_with_retry(name: str, collector, retries: int, retry_delay_seconds: float) -> tuple[str, list[dict], str | None]:
    error: str | None = None
    for attempt in range(retries + 1):
        source, events, error = _safe_collect(name, collector)
        if not error:
            return source, events, None
        if attempt < retries:
            sleep(retry_delay_seconds)
    return name, [], error


def _persist_events(events: list[dict]) -> str:
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    path = data_dir / "last_run_events.json"
    path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    return str(path)


def _ingest_events(events: list[dict]) -> dict:
    ingest_url = os.getenv("BACKEND_INGEST_URL", "http://localhost:8000/api/v1/osint/events/ingest/")
    timeout_seconds = int(os.getenv("INGEST_TIMEOUT_SECONDS", "30"))

    if not events:
        return {"ingested": 0, "url": ingest_url, "status": "skipped_no_events"}

    response = requests.post(
        ingest_url,
        json=events,
        headers={"X-Debug-Role": os.getenv("SCRAPER_DEBUG_ROLE", "analyst")},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    payload = response.json()
    return {"ingested": payload.get("created_count", 0), "url": ingest_url, "status": "ok"}


def run_collection_cycle(retries: int = 1, retry_delay_seconds: float = 1.5) -> dict:
    collectors = [
        ("tzcert", collect_tzcert_events),
        ("abuseipdb", collect_abuseipdb_events),
        ("otx", collect_otx_events),
        ("nvd", collect_nvd_events),
        ("acled", collect_acled_events),
    ]

    raw_events: list[dict] = []
    errors: dict[str, str] = {}
    source_counts: dict[str, int] = {}

    for name, fn in collectors:
        source, events, error = _collect_with_retry(name, fn, retries=retries, retry_delay_seconds=retry_delay_seconds)
        raw_events.extend(events)
        source_counts[source] = len(events)
        if error:
            errors[source] = error

    normalized = normalize_events(raw_events)
    output_path = _persist_events(normalized)

    ingest_status = {"status": "not_requested"}
    if os.getenv("ENABLE_BACKEND_INGEST", "true").lower() == "true":
        try:
            ingest_status = _ingest_events(normalized)
        except Exception as exc:  # noqa: BLE001
            ingest_status = {"status": "failed", "error": str(exc)}

    return {
        "service": "scrapers",
        "status": "completed",
        "source_counts": source_counts,
        "normalized_events": len(normalized),
        "output_file": output_path,
        "ingest": ingest_status,
        "errors": errors,
    }


def main() -> None:
    retries = int(os.getenv("SCRAPER_RETRIES", "1"))
    retry_delay_seconds = float(os.getenv("SCRAPER_RETRY_DELAY_SECONDS", "1.5"))
    print(run_collection_cycle(retries=retries, retry_delay_seconds=retry_delay_seconds))


if __name__ == "__main__":
    main()
