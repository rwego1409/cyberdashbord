from django.urls import path

from consent.views import ConsentGrantCreateView, ConsentGrantListView, ConsentStatusView


urlpatterns = [
    path("grants/", ConsentGrantCreateView.as_view(), name="consent-create"),
    path("grants/list/", ConsentGrantListView.as_view(), name="consent-list"),
    path("status/", ConsentStatusView.as_view(), name="consent-status"),
]
