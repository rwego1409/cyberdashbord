from django.urls import path

from osint.views import OsintSummaryView, SourceHealthView, ThreatEventIngestView, ThreatEventListView


urlpatterns = [
    path("events/ingest/", ThreatEventIngestView.as_view(), name="osint-ingest"),
    path("events/", ThreatEventListView.as_view(), name="osint-list"),
    path("summary/", OsintSummaryView.as_view(), name="osint-summary"),
    path("sources-health/", SourceHealthView.as_view(), name="osint-sources-health"),
]
