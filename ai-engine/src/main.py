import os

import requests

from models.gemini_advisor import GeminiRiskAdvisor
from models.risk_model import derive_snapshot_rows


def main() -> None:
    api_base = os.getenv("TCIO_API_BASE_URL", "http://localhost:8000/api/v1")
    headers = {"X-Debug-Role": os.getenv("AI_DEBUG_ROLE", "analyst")}

    risk_resp = requests.get(f"{api_base}/analytics/risk-overview/", timeout=30)
    risk_resp.raise_for_status()
    risk_overview = risk_resp.json()

    advisor = GeminiRiskAdvisor(timeout_seconds=int(os.getenv("GEMINI_TIMEOUT_SECONDS", "45")))
    ai_analysis = advisor.analyze(risk_overview)

    rows = derive_snapshot_rows(
        risk_overview,
        region_adjustments=ai_analysis.get("regional_adjustments", {}),
    )
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
            "ai_enabled": ai_analysis.get("enabled", False),
            "ai_model": ai_analysis.get("model"),
            "ai_summary": ai_analysis.get("summary"),
            "ai_regional_adjustments": ai_analysis.get("regional_adjustments", {}),
            "derived_rows": len(rows),
            "ingest_result": ingest_result,
        }
    )


if __name__ == "__main__":
    main()
