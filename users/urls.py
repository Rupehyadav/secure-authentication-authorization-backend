from django.urls import path
from .views import register_user, login_user, verify_email, verify_2fa, resend_2fa_code

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('login/', login_user, name='login_user'),
    path('verify-email/<str:token>/', verify_email, name='verify_email'),
    path('verify-2fa/', verify_2fa, name='verify_2fa'),
    path('resend-2fa/', resend_2fa_code, name='resend_2fa_code')
]
