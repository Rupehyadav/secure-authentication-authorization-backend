from django.urls import path
from .views import register_user, login_user, verify_email

urlpatterns = [
    path('register/', register_user, name='register_user'),  # Registration route
    path('login/', login_user, name='login_user'),           # Login route
    path('verify-email/<str:token>/', verify_email, name='verify_email'),  # Email verification route
]
