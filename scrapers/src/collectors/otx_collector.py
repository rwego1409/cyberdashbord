from datetime import datetime, timezone
import os

import requests


def collect_otx_events(timeout_seconds: int = 20) -> list[dict]:
    api_key = os.getenv("OTX_API_KEY", "").strip()
    if not api_key:
        return []

    response = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={"X-OTX-API-KEY": api_key},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    payload = response.json()

    events: list[dict] = []
    for pulse in payload.get("results", [])[:20]:
        indicators = pulse.get("indicators", [])
        for indicator in indicators[:5]:
            events.append(
                {
                    "source": "otx",
                    "event_type": pulse.get("name", "otx_pulse")[:64],
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "country_code": "UNK",
                    "region": "",
                    "district": "",
                    "ward": "",
                    "indicator": indicator.get("type", "")[:64],
                    "value": indicator.get("indicator", "")[:255],
                    "severity_score": 5.0,
                    "raw_payload": {"pulse_id": pulse.get("id"), "indicator": indicator},
                }
            )
    return events
