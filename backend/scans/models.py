from django.db import models

from authn.models import Organization
from consent.models import ConsentGrant


class Asset(models.Model):
    TYPE_CHOICES = [
        ("ip", "IP"),
        ("cidr", "CIDR"),
        ("domain", "Domain"),
        ("system", "System"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name="assets")
    name = models.CharField(max_length=255, blank=True)
    asset_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    value = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "asset_type", "value"], name="uq_asset_org_type_value")
        ]

    def __str__(self) -> str:
        return f"{self.asset_type}:{self.value}"


class ScanJob(models.Model):
    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
        ("blocked", "Blocked"),
    ]
    SCANNER_CHOICES = [
        ("nmap", "Nmap"),
        ("openvas", "OpenVAS"),
        ("vulners", "Vulners"),
    ]

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="scan_jobs")
    consent = models.ForeignKey(ConsentGrant, on_delete=models.PROTECT, related_name="scan_jobs")
    scanner_type = models.CharField(max_length=20, choices=SCANNER_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="queued")
    requested_by = models.CharField(max_length=150, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"scan#{self.id} {self.scanner_type} {self.status}"


class ScanFinding(models.Model):
    SEVERITY_CHOICES = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
    ]

    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="findings")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=255)
    cve = models.CharField(max_length=32, blank=True)
    port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=16, blank=True)
    recommendation = models.TextField(blank=True)
    reference = models.URLField(blank=True)
    is_patch_available = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.severity}:{self.title}"
