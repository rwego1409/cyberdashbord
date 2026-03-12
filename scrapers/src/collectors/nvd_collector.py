from datetime import datetime, timezone

import requests


def collect_nvd_events(timeout_seconds: int = 20) -> list[dict]:
    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"resultsPerPage": 20},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    payload = response.json()

    events: list[dict] = []
    for vuln in payload.get("vulnerabilities", [])[:20]:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})
        base_score = 0.0
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            base_score = float(cvss_v31[0].get("cvssData", {}).get("baseScore", 0))

        events.append(
            {
                "source": "nvd",
                "event_type": "cve_disclosure",
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "country_code": "GLOBAL",
                "region": "",
                "district": "",
                "ward": "",
                "indicator": "cve",
                "value": cve_id[:255],
                "severity_score": base_score,
                "raw_payload": cve,
            }
        )
    return events
