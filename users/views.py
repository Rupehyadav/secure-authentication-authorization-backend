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
        user.is_verified = True  # Mark the user as verified
        user.save()
        return Response({'message': 'Email verified successfully!'}, status=200)
    
    return Response({'error': 'Invalid or expired token.'}, status=400)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        # Check if 2FA is required
        validated_data = serializer.validated_data
        print("========================== cehcking 2f a required or not")
        print("==================", "2fa_required" in validated_data and validated_data['2fa_required'])
        if '2fa_required' in validated_data and validated_data['2fa_required']:
            # 2FA is required, do not return tokens yet, just return a message
            return Response({
                'message': validated_data['message'],
                '2fa_required': True,
                'two_factor_code': validated_data.get('two_factor_code')  # For debugging (shouldn't be exposed in prod)
            }, status=status.HTTP_200_OK)
        
        # If 2FA is not required, return the tokens
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
            'message': '2FA verification successful.',
            'tokens': tokens
        }, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Invalid or expired 2FA code.'}, status=status.HTTP_400_BAD_REQUEST)
