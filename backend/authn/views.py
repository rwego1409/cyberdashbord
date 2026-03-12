from django.contrib.auth.models import User
from django.db.models import Count
from rest_framework import serializers, status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.models import AuditLog
from authn.models import Organization, UserProfile
from common.permissions import IsOperatorOrDebugRole


class BootstrapUserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128)
    email = serializers.EmailField(required=False, allow_blank=True)
    role = serializers.ChoiceField(choices=UserProfile.ROLE_CHOICES, default="analyst")
    organization = serializers.CharField(max_length=255, required=False, allow_blank=True)


class BootstrapUserView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = BootstrapUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data

        user, created = User.objects.get_or_create(
            username=payload["username"],
            defaults={"email": payload.get("email", "")},
        )
        if created:
            user.set_password(payload["password"])
            user.save(update_fields=["password"])

        if not created and payload.get("password"):
            user.set_password(payload["password"])
            user.save(update_fields=["password"])

        org_obj = None
        organization_name = payload.get("organization", "").strip()
        if organization_name:
            org_obj, _ = Organization.objects.get_or_create(name=organization_name)

        profile, _ = UserProfile.objects.get_or_create(
            username=user.username,
            defaults={
                "user": user,
                "email": payload.get("email", ""),
                "role": payload["role"],
                "organization": org_obj,
            },
        )
        profile.user = user
        profile.email = payload.get("email", profile.email)
        profile.role = payload["role"]
        profile.organization = org_obj
        profile.save(update_fields=["user", "email", "role", "organization", "updated_at"])

        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {
                "username": user.username,
                "role": profile.role,
                "organization": profile.organization.name if profile.organization else None,
                "token": token.key,
            },
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class TokenLoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = Token.objects.filter(key=response.data["token"]).select_related("user").first()
        profile = UserProfile.objects.filter(username=token.user.username).first() if token else None
        return Response(
            {
                "token": response.data["token"],
                "username": token.user.username if token else None,
                "role": profile.role if profile else "viewer",
            }
        )


class ProfileView(APIView):
    def get(self, request):
        if request.user.is_authenticated:
            profile = UserProfile.objects.filter(username=request.user.username).first()
            return Response(
                {
                    "user": request.user.username,
                    "role": profile.role if profile else "viewer",
                    "organization": profile.organization.name if profile and profile.organization else None,
                    "profiles_count": UserProfile.objects.count(),
                    "status": "authenticated",
                }
            )

        latest_profile = UserProfile.objects.order_by("-created_at").first()
        return Response(
            {
                "user": latest_profile.username if latest_profile else "anonymous",
                "role": latest_profile.role if latest_profile else "viewer",
                "organization": latest_profile.organization.name if latest_profile and latest_profile.organization else None,
                "profiles_count": UserProfile.objects.count(),
                "status": "unauthenticated",
            }
        )


class UserRoleUpdateSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=UserProfile.ROLE_CHOICES)


def _permissions_for_role(role: str) -> list[str]:
    if role == "owner":
        return ["all"]
    if role == "analyst":
        return ["view_intelligence", "run_scans", "manage_alerts", "generate_reports"]
    if role == "compliance":
        return ["view_intelligence", "view_audit", "generate_reports"]
    return ["view_intelligence"]


class UserListView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def get(self, request):
        profiles = UserProfile.objects.select_related("organization").order_by("username")
        rows = [
            {
                "name": profile.username,
                "email": profile.email,
                "role": profile.role,
                "organization": profile.organization.name if profile.organization else None,
                "permissions": _permissions_for_role(profile.role),
                "is_active": profile.is_active,
                "updated_at": profile.updated_at,
            }
            for profile in profiles
        ]
        return Response({"users": rows, "count": len(rows)})


class UserRoleUpdateView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request, username: str):
        serializer = UserRoleUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        profile = UserProfile.objects.filter(username=username).first()
        if not profile:
            return Response({"detail": "User profile not found"}, status=status.HTTP_404_NOT_FOUND)
        profile.role = serializer.validated_data["role"]
        profile.save(update_fields=["role", "updated_at"])
        return Response(
            {
                "username": profile.username,
                "role": profile.role,
                "permissions": _permissions_for_role(profile.role),
            }
        )


class OrganizationListView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def get(self, request):
        organizations = Organization.objects.order_by("name")
        rows = []
        for organization in organizations:
            rows.append(
                {
                    "name": organization.name,
                    "country_code": organization.country_code,
                    "users_count": organization.profiles.count(),
                    "assets_count": organization.assets.count(),
                    "consents_count": organization.consents.count(),
                    "created_at": organization.created_at,
                }
            )
        return Response({"organizations": rows, "count": len(rows)})


class ApiKeyListView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def get(self, request):
        tokens = Token.objects.select_related("user").order_by("-created")
        usage = {
            row["actor"]: row["count"]
            for row in AuditLog.objects.values("actor").annotate(count=Count("id"))
            if row["actor"]
        }
        rows = []
        for token in tokens:
            username = token.user.username
            rows.append(
                {
                    "username": username,
                    "api_key_preview": f"{token.key[:6]}...{token.key[-4:]}",
                    "created_at": token.created,
                    "usage_count": usage.get(username, 0),
                    "status": "active",
                }
            )
        return Response({"keys": rows, "count": len(rows)})


class ApiKeyRotateSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)


class ApiKeyRotateView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = ApiKeyRotateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]
        user = User.objects.filter(username=username).first()
        if not user:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        Token.objects.filter(user=user).delete()
        token = Token.objects.create(user=user)
        return Response(
            {
                "username": username,
                "api_key_preview": f"{token.key[:6]}...{token.key[-4:]}",
                "status": "rotated",
            }
        )


class ApiKeyRevokeView(APIView):
    permission_classes = [IsOperatorOrDebugRole]

    def post(self, request):
        serializer = ApiKeyRotateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]
        user = User.objects.filter(username=username).first()
        if not user:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        deleted, _ = Token.objects.filter(user=user).delete()
        return Response({"username": username, "deleted_tokens": deleted, "status": "revoked"})
