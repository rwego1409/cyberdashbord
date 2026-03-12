from django.contrib import admin

from alerts.models import AlertEvent, AlertRule

admin.site.register(AlertRule)
admin.site.register(AlertEvent)
