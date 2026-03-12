from django.db import models


class AlertRule(models.Model):
    CHANNEL_CHOICES = [
        ("email", "Email"),
        ("telegram", "Telegram"),
        ("webhook", "Webhook"),
    ]
    SCOPE_CHOICES = [
        ("national", "National"),
        ("regional", "Regional"),
        ("asset", "Asset"),
    ]

    name = models.CharField(max_length=150, unique=True)
    scope = models.CharField(max_length=20, choices=SCOPE_CHOICES, default="national")
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES, default="email")
    threshold = models.FloatField(default=1.0)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


class AlertEvent(models.Model):
    STATUS_CHOICES = [
        ("open", "Open"),
        ("acknowledged", "Acknowledged"),
        ("resolved", "Resolved"),
    ]
    SEVERITY_CHOICES = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
    ]

    rule = models.ForeignKey(AlertRule, on_delete=models.SET_NULL, null=True, blank=True, related_name="events")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=255)
    details = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="open")
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["status", "severity", "created_at"])]

    def __str__(self) -> str:
        return f"{self.severity}:{self.title}"
