from django.urls import path

from analytics.views import RiskOverviewView, SnapshotGenerateView, SnapshotIngestView, SnapshotListView


urlpatterns = [
    path("risk-overview/", RiskOverviewView.as_view(), name="risk-overview"),
    path("snapshots/", SnapshotListView.as_view(), name="snapshot-list"),
    path("snapshots/ingest/", SnapshotIngestView.as_view(), name="snapshot-ingest"),
    path("snapshots/generate/", SnapshotGenerateView.as_view(), name="snapshot-generate"),
]
