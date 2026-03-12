from django.db import models


class RegionalRiskSnapshot(models.Model):
    country_code = models.CharField(max_length=3, default="TZ")
    region = models.CharField(max_length=128, blank=True)
    period_start = models.DateField()
    period_end = models.DateField()
    attack_volume = models.PositiveIntegerField(default=0)
    malware_volume = models.PositiveIntegerField(default=0)
    exposure_score = models.FloatField(default=0.0)
    risk_index = models.FloatField(default=0.0)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["country_code", "region", "period_end"])]

    def __str__(self) -> str:
        return f"{self.country_code}:{self.region or 'national'}:{self.risk_index}"
