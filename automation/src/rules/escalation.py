def evaluate_escalation(alert: dict) -> dict:
    severity = str(alert.get("severity", "info")).lower()
    if severity == "critical":
        return {"channel": "telegram", "priority": "p1"}
    if severity == "high":
        return {"channel": "email", "priority": "p2"}
    if severity == "medium":
        return {"channel": "webhook", "priority": "p3"}
    return {"channel": "webhook", "priority": "p4"}
