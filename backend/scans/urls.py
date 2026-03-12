from django.urls import path

from scans.views import (
    ScanFindingListView,
    ScanJobCompleteView,
    ScanJobCreateView,
    ScanJobListView,
    ScanJobProgressView,
    ScanProcessAsyncView,
    ScanProcessOnceView,
    ScanJobReserveView,
    ScanSummaryView,
)


urlpatterns = [
    path("jobs/", ScanJobCreateView.as_view(), name="scan-create"),
    path("jobs/list/", ScanJobListView.as_view(), name="scan-list"),
    path("findings/", ScanFindingListView.as_view(), name="scan-findings"),
    path("jobs/<int:job_id>/progress/", ScanJobProgressView.as_view(), name="scan-progress"),
    path("jobs/reserve/", ScanJobReserveView.as_view(), name="scan-reserve"),
    path("jobs/process-once/", ScanProcessOnceView.as_view(), name="scan-process-once"),
    path("jobs/process-async/", ScanProcessAsyncView.as_view(), name="scan-process-async"),
    path("jobs/<int:job_id>/complete/", ScanJobCompleteView.as_view(), name="scan-complete"),
    path("summary/", ScanSummaryView.as_view(), name="scan-summary"),
]
