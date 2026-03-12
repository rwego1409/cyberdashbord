from django.urls import path

from alerts.views import AcknowledgeAlertView, ActiveAlertsView, DispatchAlertsView


urlpatterns = [
    path("active/", ActiveAlertsView.as_view(), name="alerts-active"),
    path("dispatch/", DispatchAlertsView.as_view(), name="alerts-dispatch"),
    path("<int:alert_id>/ack/", AcknowledgeAlertView.as_view(), name="alerts-ack"),
]
