from django.db import models
from django.utils import timezone
import uuid

from authn.models import Organization


class ConsentGrant(models.Model):
    STATUS_CHOICES = [
        ("active", "Active"),
        ("revoked", "Revoked"),
        ("expired", "Expired"),
    ]
    SOURCE_CHOICES = [
        ("manual", "Manual"),
        ("smart_contract", "Smart Contract"),
    ]

    consent_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="consents")
    requester_name = models.CharField(max_length=150, blank=True)
    requester_email = models.EmailField(blank=True)
    target = models.CharField(max_length=255, help_text="IP, CIDR, domain, or wildcard target")
    allowed_scanners = models.JSONField(default=list, blank=True)
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default="manual")
    blockchain_tx_hash = models.CharField(max_length=128, blank=True)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.consent_id} -> {self.target}"
