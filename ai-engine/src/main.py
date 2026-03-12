import os

import requests

from models.risk_model import derive_snapshot_rows


def main() -> None:
    api_base = os.getenv("TCIO_API_BASE_URL", "http://localhost:8000/api/v1")
    headers = {"X-Debug-Role": os.getenv("AI_DEBUG_ROLE", "analyst")}

    risk_resp = requests.get(f"{api_base}/analytics/risk-overview/", timeout=30)
    risk_resp.raise_for_status()
    risk_overview = risk_resp.json()

    rows = derive_snapshot_rows(risk_overview)
    ingest_result = {"created_count": 0}
    if rows:
        ingest_resp = requests.post(
            f"{api_base}/analytics/snapshots/ingest/",
            headers=headers,
            json=rows,
            timeout=30,
        )
        ingest_resp.raise_for_status()
        ingest_result = ingest_resp.json()

    print(
        {
            "service": "ai-engine",
            "status": "completed",
            "national_risk_index": risk_overview.get("national_risk_index"),
            "derived_rows": len(rows),
            "ingest_result": ingest_result,
        }
    )


if __name__ == "__main__":
    main()
