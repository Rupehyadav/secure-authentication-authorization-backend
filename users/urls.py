from django.urls import path
from .views import register_user, login_user, verify_email, verify_2fa

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('login/', login_user, name='login_user'),
    path('verify-email/<str:token>/', verify_email, name='verify_email'),
    path('verify-2fa/', verify_2fa, name='verify_2fa')
]
