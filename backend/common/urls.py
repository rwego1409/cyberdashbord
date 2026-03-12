from django.urls import path

from common.views import HealthView, SystemMetricsView


urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("system/metrics/", SystemMetricsView.as_view(), name="system-metrics"),
]
