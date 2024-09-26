# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser

class CustomUserAdmin(BaseUserAdmin):
    # Define your custom fieldsets to avoid referencing fields that don't exist in CustomUser
    fieldsets = (
        (None, {'fields': ('username', 'password', 'is_2fa_enabled')}),
        ('Personal info', {'fields': ('email',)}),  # Add any other fields that exist in CustomUser
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),
        ('Important dates', {'fields': ('last_login',)}),  # You can include date fields that exist
    )

    # Display 'is_2fa_enabled' in the list view
    list_display = ('username', 'email', 'is_2fa_enabled', 'is_staff', 'is_active')
    list_filter = ('is_2fa_enabled', 'is_staff', 'is_active')  # Add filters for easier navigation

# Register the CustomUser model with the custom admin class
admin.site.register(CustomUser, CustomUserAdmin)
