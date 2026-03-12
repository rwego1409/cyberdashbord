from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("common.urls")),
    path("api/v1/authn/", include("authn.urls")),
    path("api/v1/audit/", include("audit.urls")),
    path("api/v1/osint/", include("osint.urls")),
    path("api/v1/scans/", include("scans.urls")),
    path("api/v1/analytics/", include("analytics.urls")),
    path("api/v1/alerts/", include("alerts.urls")),
    path("api/v1/consent/", include("consent.urls")),
    path("api/v1/reports/", include("reports.urls")),
]
