from datetime import timedelta

from django.db.models import Avg, Count, Q
from django.utils import timezone

from analytics.models import RegionalRiskSnapshot
from osint.models import ThreatEvent


def generate_regional_snapshots(days: int = 30) -> dict:
    end_day = timezone.now().date()
    start_day = end_day - timedelta(days=days)

    by_region = (
        ThreatEvent.objects.filter(occurred_at__date__gte=start_day, occurred_at__date__lte=end_day)
        .exclude(region="")
        .values("country_code", "region")
        .annotate(
            attack_volume=Count("id"),
            avg_severity=Avg("severity_score"),
            malware_volume=Count("id", filter=Q(event_type__icontains="malware")),
        )
    )

    created = 0
    for row in by_region:
        avg_sev = float(row.get("avg_severity") or 0.0)
        risk_index = round((avg_sev * 8) + row["attack_volume"] * 0.15 + row["malware_volume"] * 0.4, 2)
        RegionalRiskSnapshot.objects.create(
            country_code=row["country_code"] or "TZ",
            region=row["region"] or "",
            period_start=start_day,
            period_end=end_day,
            attack_volume=row["attack_volume"],
            malware_volume=row["malware_volume"],
            exposure_score=avg_sev,
            risk_index=risk_index,
        )
        created += 1

    return {
        "generated": created,
        "period_start": start_day,
        "period_end": end_day,
        "status": "ok",
    }
