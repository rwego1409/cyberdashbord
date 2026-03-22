from datetime import date
from typing import Mapping


def _baseline_risk_index(avg_sev: float, events: int, critical: int, malware_volume: int) -> float:
    return round((avg_sev * 8) + (events * 0.2) + (critical * 0.8) + (malware_volume * 0.35), 2)


def _current_year_window() -> tuple[str, str]:
    this_year = date.today().year
    return f"{this_year}-01-01", f"{this_year}-12-31"


def derive_snapshot_rows(
    risk_overview: dict,
    region_adjustments: Mapping[str, float] | None = None,
) -> list[dict]:
    adjustments = region_adjustments or {}
    period_start, period_end = _current_year_window()
    rows = []

    for item in risk_overview.get("regional_comparison", []):
        avg_sev = float(item.get("avg_severity") or 0.0)
        events = int(item.get("events") or 0)
        critical = int(item.get("critical_events") or 0)
        malware_volume = int(item.get("malware_volume") or 0)
        region = str(item.get("region", ""))

        baseline = _baseline_risk_index(avg_sev, events, critical, malware_volume)
        adjusted_risk = max(0.0, round(baseline + float(adjustments.get(region, 0.0)), 2))

        rows.append(
            {
                "country_code": item.get("country_code", "TZ"),
                "region": region,
                "period_start": period_start,
                "period_end": period_end,
                "attack_volume": events,
                "malware_volume": malware_volume,
                "exposure_score": avg_sev,
                "risk_index": adjusted_risk,
            }
        )
    return rows
