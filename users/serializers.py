import random
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed

from .models import CustomUser


class RegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration. Ensures that password is hashed and 
    the user is marked as unverified initially.
    """
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'phone_number', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            phone_number=validated_data['phone_number'],
            password=validated_data['password'],
        )
        user.is_verified = False
        user.save()
        return user

    def validate_password(self, value):
        """
        Validate that the password meets certain criteria, e.g., minimum length.
        """
        if len(value) < 6:
            raise serializers.ValidationError("Password must be at least 6 characters long.")
        return value


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for representing user information, including verification status.
    """
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'phone_number', 'is_verified']


def get_tokens_for_user(user):
    """
    This function generates a JWT token (access and refresh) for the user.
    """
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def get_tokens_for_user(self, user):
        """
        Generates a JWT token (access and refresh) for the user.
        """
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    def generate_2fa_code(self, user):
        """
        Generates a 2FA code and sets its expiration.
        """
        code = str(random.randint(100000, 999999))
        user.two_factor_code = code
        user.two_factor_code_expires = timezone.now() + timedelta(minutes=10)
        user.save()
        return code

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = authenticate(username=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, please try again.')

        if not user.is_verified:
            raise AuthenticationFailed('Email not verified. Please verify your email to log in.')

        if user.is_2fa_enabled:
            two_factor_code = self.generate_2fa_code(user)

            send_mail(
                subject="Your 2FA Verification Code",
                message=f"Your 2FA verification code is {two_factor_code}. This code will expire in 10 minutes.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            ) 
            return {
                'email': user.email,
                'username': user.username,
                '2fa_required': True,
                'message': '2FA code sent. Please verify the code.',
            }

        tokens = self.get_tokens_for_user(user)

        return {
            'email': user.email,
            'username': user.username,
            'tokens': tokens
        }


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer to handle email verification
    """
    token = serializers.CharField()

