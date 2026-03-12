from datetime import datetime, timezone
import os

import requests


def collect_abuseipdb_events(timeout_seconds: int = 20) -> list[dict]:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return []

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers={
            "Key": api_key,
            "Accept": "application/json",
        },
        params={"confidenceMinimum": 90, "limit": 50},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    payload = response.json()

    events: list[dict] = []
    for row in payload.get("data", [])[:50]:
        events.append(
            {
                "source": "abuseipdb",
                "event_type": "malicious_ip",
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "country_code": row.get("countryCode", "UNK")[:3],
                "region": "",
                "district": "",
                "ward": "",
                "indicator": "ip",
                "value": row.get("ipAddress", "")[:255],
                "severity_score": float(row.get("abuseConfidenceScore", 0)) / 10.0,
                "raw_payload": row,
            }
        )
    return events
