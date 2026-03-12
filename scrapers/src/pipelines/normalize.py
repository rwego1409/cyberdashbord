from typing import Iterable


REQUIRED_KEYS = {
    "source",
    "event_type",
    "occurred_at",
    "country_code",
    "region",
    "district",
    "ward",
    "indicator",
    "value",
    "severity_score",
    "raw_payload",
}


def normalize_events(events: Iterable[dict]) -> list[dict]:
    normalized: list[dict] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        if not REQUIRED_KEYS.issubset(set(event.keys())):
            continue
        normalized.append(
            {
                "source": str(event["source"])[:32],
                "event_type": str(event["event_type"])[:64],
                "occurred_at": event["occurred_at"],
                "country_code": str(event["country_code"])[:3],
                "region": str(event["region"])[:128],
                "district": str(event["district"])[:128],
                "ward": str(event["ward"])[:128],
                "indicator": str(event["indicator"])[:64],
                "value": str(event["value"])[:255],
                "severity_score": float(event["severity_score"]),
                "raw_payload": event["raw_payload"] if isinstance(event["raw_payload"], dict) else {"value": event["raw_payload"]},
            }
        )
    return normalized
