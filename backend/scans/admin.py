from django.contrib import admin

from scans.models import Asset, ScanFinding, ScanJob

admin.site.register(Asset)
admin.site.register(ScanJob)
admin.site.register(ScanFinding)
