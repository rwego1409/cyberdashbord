from django.contrib import admin

from authn.models import Organization, UserProfile

admin.site.register(Organization)
admin.site.register(UserProfile)
