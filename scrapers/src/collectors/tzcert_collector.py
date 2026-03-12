from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup


def collect_tzcert_events(timeout_seconds: int = 20) -> list[dict]:
    url = "https://www.tzcert.go.tz/"
    response = requests.get(url, timeout=timeout_seconds)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    events: list[dict] = []
    for anchor in soup.find_all("a", href=True):
        text = anchor.get_text(strip=True).lower()
        href = anchor["href"]
        if "honeypot" in text or "report" in text:
            events.append(
                {
                    "source": "tzcert",
                    "event_type": "tzcert_report_reference",
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "country_code": "TZ",
                    "region": "",
                    "district": "",
                    "ward": "",
                    "indicator": "report_link",
                    "value": href[:255],
                    "severity_score": 2.0,
                    "raw_payload": {"label": text, "href": href},
                }
            )
    return events
