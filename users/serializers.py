from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser
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


from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login, checking for correct credentials, ensuring
    the user is verified before allowing them to log in, and returning JWT tokens.
    """

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def get_tokens_for_user(self, user):
        """
        This function generates a JWT token (access and refresh) for the user.
        """
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = authenticate(username=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, please try again.')

        if not user.is_verified:
            raise AuthenticationFailed('Email not verified. Please verify your email to log in.')

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

