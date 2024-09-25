from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed

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
        # Create the user with hashed password and default unverified status
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            phone_number=validated_data['phone_number'],
            password=validated_data['password'],
        )
        user.is_verified = False  # User is unverified until email verification
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
    """
    Serializer for user login, checking for correct credentials and ensuring
    the user is verified before allowing them to log in.
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        # Authenticate user using Django's built-in authentication method
        email = data.get('email')
        password = data.get('password')

        user = authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, please try again.')

        # Check if the user is verified
        if not user.is_verified:
            raise AuthenticationFailed('Email not verified. Please verify your email to log in.')

        return {
            'email': user.email,
            'username': user.username,
            'password': user.password,
            'is_verified': user.is_verified
        }

class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer to handle email verification
    """
    token = serializers.CharField()

