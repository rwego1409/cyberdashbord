def derive_snapshot_rows(risk_overview: dict) -> list[dict]:
    rows = []
    for item in risk_overview.get("regional_comparison", []):
        avg_sev = float(item.get("avg_severity") or 0.0)
        events = int(item.get("events") or 0)
        critical = int(item.get("critical_events") or 0)
        malware_volume = int(item.get("malware_volume") or 0)
        risk_index = round((avg_sev * 8) + (events * 0.2) + (critical * 0.8), 2)

        rows.append(
            {
                "country_code": item.get("country_code", "TZ"),
                "region": item.get("region", ""),
                "period_start": "2026-01-01",
                "period_end": "2026-12-31",
                "attack_volume": events,
                "malware_volume": malware_volume,
                "exposure_score": avg_sev,
                "risk_index": risk_index,
            }
        )
    return rows
