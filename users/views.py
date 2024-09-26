import random
import requests
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from django.conf import settings
from .serializers import RegistrationSerializer
from .utils import generate_verification_token
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import verify_token
from rest_framework import status
from .serializers import LoginSerializer



@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    
    captcha_token = request.data.get('capchaToken')
    captcha_url = 'https://www.google.com/recaptcha/api/siteverify'
    captcha_data = {
        'secret': settings.RECAPTCHA_SECRET_KEY,
        'response': captcha_token,
    }


    captcha_response = requests.post(captcha_url, data=captcha_data)
    captcha_result = captcha_response.json()

    if not captcha_result.get('success'):
        return Response({'message': 'Invalid CAPTCHA. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)

    serializer = RegistrationSerializer(data=request.data)
    
    if serializer.is_valid():
        user = serializer.save()
        
        token = generate_verification_token(user.email)
        # verification_url = f"http://localhost:8000/api/users/verify-email/{token}/"
        verification_url = f"http://localhost:5173/verify-email/{token}/"
        
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
    print(token)
    email = verify_token(token)
    if email:
        user = get_object_or_404(CustomUser, email=email)
        user.is_verified = True
        user.save()
        return Response({'message': 'Email verified successfully!'}, status=200)
    
    return Response({'error': 'Invalid or expired token.'}, status=400)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        validated_data = serializer.validated_data

        if '2fa_required' in validated_data and validated_data['2fa_required']:
            return Response({
                'message': validated_data['message'],
                'two_factor_required': True,
            }, status=status.HTTP_200_OK)
        
        return Response(validated_data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_2fa(request):
    email = request.data.get('email')
    two_factor_code = request.data.get('two_factor_code')

    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    # Check if the 2FA code matches and hasn't expired
    if user.two_factor_code == two_factor_code and timezone.now() <= user.two_factor_code_expires:
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        tokens = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        # Clear the 2FA code after successful verification
        user.two_factor_code = None
        user.two_factor_code_expires = None
        user.save()

        return Response({
            'email': user.email,
            'username': user.username,
            'message': '2FA verification successful.',
            'tokens': tokens
        }, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Invalid or expired 2FA code.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def resend_2fa_code(request):
    """
    Resend the 2FA code to the user's email if 2FA is enabled.
    """
    email = request.data.get('email')

    try:
        user = CustomUser.objects.get(email=email)

        if not user.is_2fa_enabled:
            return Response({"message": "2FA is not enabled for this user."}, status=status.HTTP_400_BAD_REQUEST)

        two_factor_code = str(random.randint(100000, 999999))
        user.two_factor_code = two_factor_code
        user.two_factor_code_expires = timezone.now() + timezone.timedelta(minutes=10)
        user.save()

        send_mail(
            subject="Your 2FA Verification Code",
            message=f"Your 2FA verification code is {two_factor_code}. This code will expire in 10 minutes.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

        return Response({
            "message": "A new 2FA code has been sent to your email.",
        }, status=status.HTTP_200_OK)

    except CustomUser.DoesNotExist:
        return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
