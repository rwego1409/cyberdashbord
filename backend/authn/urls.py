from django.urls import path

from authn.views import (
    ApiKeyListView,
    ApiKeyRevokeView,
    ApiKeyRotateView,
    BootstrapUserView,
    JwtTokenObtainView,
    JwtTokenRefreshView,
    OrganizationListView,
    ProfileView,
    TokenLoginView,
    UserListView,
    UserRoleUpdateView,
)


urlpatterns = [
    path("bootstrap/", BootstrapUserView.as_view(), name="authn-bootstrap"),
    path("token/", TokenLoginView.as_view(), name="authn-token"),
    path("jwt/", JwtTokenObtainView.as_view(), name="authn-jwt-token"),
    path("jwt/refresh/", JwtTokenRefreshView.as_view(), name="authn-jwt-refresh"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("users/", UserListView.as_view(), name="users-list"),
    path("users/<str:username>/role/", UserRoleUpdateView.as_view(), name="users-role-update"),
    path("organizations/", OrganizationListView.as_view(), name="organizations-list"),
    path("api-keys/", ApiKeyListView.as_view(), name="api-keys-list"),
    path("api-keys/rotate/", ApiKeyRotateView.as_view(), name="api-keys-rotate"),
    path("api-keys/revoke/", ApiKeyRevokeView.as_view(), name="api-keys-revoke"),
]
