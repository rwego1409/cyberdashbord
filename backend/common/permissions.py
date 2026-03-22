import os

from rest_framework.permissions import BasePermission

from authn.models import UserProfile


class IsOperatorOrDebugRole(BasePermission):
    allowed_roles = {"owner", "analyst", "compliance"}

    def has_permission(self, request, view) -> bool:
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            profile = UserProfile.objects.filter(username=user.username, is_active=True).first()
            if profile and profile.role in self.allowed_roles:
                return True

        # Keep debug-header auth enabled by default only in Django debug mode.
        debug_mode = os.getenv("DJANGO_DEBUG", "true").lower() == "true"
        default_debug_header = "true" if debug_mode else "false"
        allow_debug_header = os.getenv("ENABLE_DEBUG_ROLE_HEADER", default_debug_header).lower() == "true"
        if not allow_debug_header:
            return False

        # Dev fallback for local integration.
        debug_role = request.headers.get("X-Debug-Role", "").strip().lower()
        return debug_role in self.allowed_roles
