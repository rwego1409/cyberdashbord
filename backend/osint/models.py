from django.db import models


class ThreatEvent(models.Model):
    SOURCE_CHOICES = [
        ("tzcert", "TZ-CERT"),
        ("abuseipdb", "AbuseIPDB"),
        ("otx", "AlienVault OTX"),
        ("acled", "ACLED"),
        ("nvd", "NVD"),
        ("manual", "Manual"),
    ]

    source = models.CharField(max_length=32, choices=SOURCE_CHOICES)
    event_type = models.CharField(max_length=64)
    occurred_at = models.DateTimeField()
    country_code = models.CharField(max_length=3, default="TZ")
    region = models.CharField(max_length=128, blank=True)
    district = models.CharField(max_length=128, blank=True)
    ward = models.CharField(max_length=128, blank=True)
    indicator = models.CharField(max_length=64, blank=True)
    value = models.CharField(max_length=255, blank=True)
    severity_score = models.FloatField(default=0.0)
    raw_payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["source", "occurred_at"]),
            models.Index(fields=["country_code", "region"]),
        ]

    def __str__(self) -> str:
        return f"{self.source}:{self.event_type}@{self.occurred_at.isoformat()}"
