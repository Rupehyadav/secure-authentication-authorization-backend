from django.urls import path
from .views import register_user, login_user, verify_email

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('login/', login_user, name='login_user'),
    path('verify-email/<str:token>/', verify_email, name='verify_email'),
]
