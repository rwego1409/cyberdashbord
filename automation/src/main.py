import os

import requests

from rules.escalation import evaluate_escalation


def main() -> None:
    api_base = os.getenv("TCIO_API_BASE_URL", "http://localhost:8000/api/v1")
    headers = {"X-Debug-Role": os.getenv("AUTOMATION_DEBUG_ROLE", "analyst")}

    active_resp = requests.get(f"{api_base}/alerts/active/", timeout=30)
    active_resp.raise_for_status()
    active = active_resp.json().get("active", [])

    decision_preview = [
        {"alert_id": alert.get("id"), **evaluate_escalation(alert)}
        for alert in active[:20]
    ]

    dispatch_resp = requests.post(f"{api_base}/alerts/dispatch/", json={"limit": 20}, headers=headers, timeout=30)
    dispatch_resp.raise_for_status()
    dispatch_payload = dispatch_resp.json()

    acked = []
    for alert in active:
        if str(alert.get("severity", "")).lower() == "critical":
            ack_resp = requests.post(
                f"{api_base}/alerts/{alert['id']}/ack/",
                headers=headers,
                timeout=30,
            )
            if ack_resp.ok:
                acked.append(alert["id"])

    print(
        {
            "service": "automation",
            "status": "completed",
            "decision_preview": decision_preview,
            "dispatch": dispatch_payload,
            "acked_critical": acked,
        }
    )


if __name__ == "__main__":
    main()
