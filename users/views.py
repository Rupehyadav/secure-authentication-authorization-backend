from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from django.conf import settings
from .serializers import RegistrationSerializer, UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import generate_verification_token
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import CustomUser
from .utils import verify_token
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from .serializers import LoginSerializer


@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    serializer = RegistrationSerializer(data=request.data)
    
    if serializer.is_valid():
        user = serializer.save()
        
        # Generate email verification token
        token = generate_verification_token(user.email)
        verification_url = f"http://localhost:8000/api/users/verify-email/{token}/"
        
        # Send email with verification link
        send_mail(
            subject='Verify your email',
            message=f'Click the link to verify your email: {verification_url}',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        
        return Response({'message': 'User registered successfully! Please verify your email.'}, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    email = verify_token(token)
    if email:
        user = get_object_or_404(CustomUser, email=email)
        user.is_verified = True  # Mark the user as verified
        user.save()
        return Response({'message': 'Email verified successfully!'}, status=200)
    
    return Response({'error': 'Invalid or expired token.'}, status=400)


def get_tokens_for_user(user):
    """
    This function generates a JWT token (access and refresh) for the user.
    """
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Authenticate user
        user = authenticate(email=email, password=password)
        
        if user is not None:
            if user.is_verified:  # Ensure the user has verified their email
                tokens = get_tokens_for_user(user)  # Get the tokens
                return Response({
                    'message': 'Login successful',
                    'tokens': tokens,
                    'user': {
                        'username': user.username,
                        'email': user.email,
                        'is_verified': user.is_verified,
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Email not verified.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
