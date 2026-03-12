from django.db import models


class AuditLog(models.Model):
    OUTCOME_CHOICES = [
        ("success", "Success"),
        ("failure", "Failure"),
    ]

    actor = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=100)
    target_type = models.CharField(max_length=100, blank=True)
    target_id = models.CharField(max_length=100, blank=True)
    outcome = models.CharField(max_length=20, choices=OUTCOME_CHOICES, default="success")
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["action", "created_at"])]

    def __str__(self) -> str:
        return f"{self.action}:{self.outcome}"
