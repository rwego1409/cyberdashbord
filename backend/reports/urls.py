from django.urls import path

from reports.views import ReportExportLedgerView, ReportExportView, ReportsSummaryView


urlpatterns = [
    path("summary/", ReportsSummaryView.as_view(), name="reports-summary"),
    path("export/", ReportExportView.as_view(), name="reports-export"),
    path("exports/ledger/", ReportExportLedgerView.as_view(), name="reports-export-ledger"),
]
