from datetime import datetime, timezone
import os

import requests


def collect_acled_events(timeout_seconds: int = 20) -> list[dict]:
    api_key = os.getenv("ACLED_API_KEY", "").strip()
    email = os.getenv("ACLED_EMAIL", "").strip()
    if not api_key or not email:
        return []

    response = requests.get(
        "https://api.acleddata.com/acled/read",
        params={
            "key": api_key,
            "email": email,
            "limit": 50,
            "country": "Tanzania",
            "event_date_where": ">=",
            "event_date": "2025-01-01",
        },
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    payload = response.json()

    events: list[dict] = []
    for event in payload.get("data", [])[:50]:
        events.append(
            {
                "source": "acled",
                "event_type": event.get("event_type", "acled_event")[:64],
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "country_code": "TZ",
                "region": (event.get("admin1") or "")[:128],
                "district": (event.get("admin2") or "")[:128],
                "ward": (event.get("location") or "")[:128],
                "indicator": "event_id",
                "value": str(event.get("event_id_cnty", ""))[:255],
                "severity_score": 6.0 if event.get("fatalities", "0") not in ("0", 0, None) else 3.0,
                "raw_payload": event,
            }
        )
    return events
