from django.urls import path
from django.contrib.auth import views as auth_views
from .views import register_user, login_user, verify_email, verify_2fa, resend_2fa_code, forgot_password, reset_password

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('login/', login_user, name='login_user'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('reset-password/', reset_password, name='reset_password'),
    path('verify-email/<str:token>/', verify_email, name='verify_email'),
    path('verify-2fa/', verify_2fa, name='verify_2fa'),
    path('resend-2fa/', resend_2fa_code, name='resend_2fa_code'),
    path(
        'reset-password-confirm/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(),
        name='password_reset_confirm'
    ),
]
