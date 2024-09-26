from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser

class CustomUserAdmin(BaseUserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password', 'is_2fa_enabled')}),
        ('Personal info', {'fields': ('email',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),
        ('Important dates', {'fields': ('last_login',)}),
    )

    list_display = ('username', 'email', 'is_2fa_enabled', 'is_staff', 'is_active')
    list_filter = ('is_2fa_enabled', 'is_staff', 'is_active')

admin.site.register(CustomUser, CustomUserAdmin)
