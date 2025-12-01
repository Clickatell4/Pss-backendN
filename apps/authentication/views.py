from django.contrib.auth import authenticate, get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from apps.users.serializers import UserSerializer
from apps.users.permissions import IsSuperuser, IsAdminOrSuperuser
from pss_backend.throttles import AuthRateThrottle, RegisterRateThrottle
from pss_backend.validators import sanitize_text, validate_email_domain, validate_text_length
from pss_backend.captcha import (
    verify_captcha,
    track_failed_login_attempt,
    reset_failed_login_attempts,
    is_captcha_required,
    get_client_ip,
    create_login_identifier,
    CaptchaVerificationError
)
from django.core.exceptions import ValidationError
import logging

User = get_user_model()
logger = logging.getLogger('django.security.auth')

class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthRateThrottle]  # SCRUM-10: Rate limit login attempts

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        captcha_token = request.data.get('captcha_token')

        if not email or not password:
            return Response({
                'detail': 'Email and password are required',
                'errors': {
                    'email': ['This field is required.'] if not email else [],
                    'password': ['This field is required.'] if not password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Sanitize and validate email
        try:
            email = sanitize_text(email, max_length=255)
            email = validate_email_domain(email, allowed_domains=['capaciti.org.za'])
        except ValidationError as e:
            return Response({
                'detail': 'Invalid email',
                'errors': {'email': [str(e)]}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate password length (prevent DoS with huge passwords)
        try:
            validate_text_length(password, max_length=128, field_name='Password')
        except ValidationError as e:
            return Response({
                'detail': 'Invalid password',
                'errors': {'password': [str(e)]}
            }, status=status.HTTP_400_BAD_REQUEST)

        # SCRUM-120: CAPTCHA verification for brute force protection
        client_ip = get_client_ip(request)
        login_identifier = create_login_identifier(client_ip, email)

        # Check if CAPTCHA is required based on failed attempts
        captcha_required = is_captcha_required(login_identifier)

        if captcha_required:
            if not captcha_token:
                logger.warning(
                    f'CAPTCHA required but not provided for login attempt: {email} from {client_ip}'
                )
                return Response({
                    'detail': 'Security verification required',
                    'captcha_required': True,
                    'message': 'Too many failed attempts. Please complete the security check.'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Verify CAPTCHA
            try:
                success, score, error_message = verify_captcha(
                    captcha_token,
                    action='login',
                    remote_ip=client_ip
                )

                if not success:
                    logger.warning(
                        f'CAPTCHA verification failed for {email} from {client_ip}: {error_message}'
                    )
                    return Response({
                        'detail': 'Security verification failed',
                        'captcha_required': True,
                        'message': 'Please try again or contact support if you continue to have issues.'
                    }, status=status.HTTP_400_BAD_REQUEST)

                logger.info(f'CAPTCHA verified successfully for {email} (score: {score})')

            except CaptchaVerificationError as e:
                logger.error(f'CAPTCHA service error for {email}: {str(e)}')
                # Allow login to proceed if CAPTCHA service is down (fail open)
                # but log for monitoring
                pass

        try:
            user = authenticate(request, username=email, password=password)

            if user is not None:
                if not user.is_active:
                    return Response({
                        'detail': 'Account is deactivated'
                    }, status=status.HTTP_401_UNAUTHORIZED)

                # Successful login - reset failed attempts
                reset_failed_login_attempts(login_identifier)
                logger.info(f'Successful login: {email} from {client_ip}')

                refresh = RefreshToken.for_user(user)
                user_data = UserSerializer(user).data
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': user_data
                }, status=status.HTTP_200_OK)
            else:
                # Failed login - track attempt
                attempts = track_failed_login_attempt(login_identifier)
                logger.warning(
                    f'Failed login attempt: {email} from {client_ip} ({attempts} attempts)'
                )

                # Check if CAPTCHA will be required on next attempt
                will_require_captcha = attempts >= 3

                response_data = {
                    'detail': 'Invalid email or password'
                }

                # Inform frontend if CAPTCHA will be required next time
                if will_require_captcha:
                    response_data['captcha_required'] = True
                    response_data['message'] = 'Too many failed attempts. CAPTCHA will be required for next login.'

                return Response(response_data, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            logger.error(f'Authentication error for {email}: {str(e)}')
            return Response({
                'detail': 'Authentication error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            return Response({'detail': 'Successfully logged out'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [RegisterRateThrottle]  # SCRUM-10: Rate limit registration attempts

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        # Security: Public registration only creates 'candidate' role accounts
        # Admin/superuser accounts must be created through protected endpoints
        role = 'candidate'

        # Validation
        if not email or not password:
            return Response({
                'error': 'Email and password are required',
                'errors': {
                    'email': ['This field is required.'] if not email else [],
                    'password': ['This field is required.'] if not password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Sanitize and validate email
        try:
            email = sanitize_text(email, max_length=255)
            email = validate_email_domain(email, allowed_domains=['capaciti.org.za'])
        except ValidationError as e:
            return Response({
                'error': 'Invalid email',
                'errors': {'email': [str(e)]}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate password length
        try:
            validate_text_length(password, min_length=8, max_length=128, field_name='Password')
        except ValidationError as e:
            return Response({
                'error': 'Invalid password',
                'errors': {'password': [str(e)]}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Sanitize name fields
        try:
            if first_name:
                first_name = sanitize_text(first_name, max_length=150)
            if last_name:
                last_name = sanitize_text(last_name, max_length=150)
        except ValidationError as e:
            return Response({
                'error': 'Invalid name',
                'errors': {'name': [str(e)]}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response({
                'error': 'User with this email already exists',
                'errors': {'email': ['A user with this email already exists.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create user with 'candidate' role only
            user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role=role
            )

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            user_data = UserSerializer(user).data

            return Response({
                'user': user_data,
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }, status=status.HTTP_201_CREATED)

        except Exception:
            return Response({
                'error': 'Failed to create user'
            }, status=status.HTTP_400_BAD_REQUEST)


class CreateAdminView(APIView):
    """
    Protected endpoint for creating admin accounts.
    Only superusers can create admin accounts.
    """
    permission_classes = [IsSuperuser]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        # Validation
        if not email or not password:
            return Response({
                'error': 'Email and password are required',
                'errors': {
                    'email': ['This field is required.'] if not email else [],
                    'password': ['This field is required.'] if not password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        if '@' not in email:
            return Response({
                'error': 'Invalid email format',
                'errors': {'email': ['Enter a valid email address.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate CAPACITI email domain
        if not email.endswith('@capaciti.org.za'):
            return Response({
                'error': 'Only CAPACITI email addresses are allowed',
                'errors': {'email': ['Email must be a CAPACITI email address (@capaciti.org.za)']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response({
                'error': 'User with this email already exists',
                'errors': {'email': ['A user with this email already exists.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create admin user
            user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role='admin'
            )

            user_data = UserSerializer(user).data

            return Response({
                'message': 'Admin user created successfully',
                'user': user_data
            }, status=status.HTTP_201_CREATED)

        except Exception:
            return Response({
                'error': 'Failed to create admin user'
            }, status=status.HTTP_400_BAD_REQUEST)


class CreateSuperuserView(APIView):
    """
    Protected endpoint for creating superuser accounts.
    Only existing superusers can create new superuser accounts.
    """
    permission_classes = [IsSuperuser]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        # Validation
        if not email or not password:
            return Response({
                'error': 'Email and password are required',
                'errors': {
                    'email': ['This field is required.'] if not email else [],
                    'password': ['This field is required.'] if not password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        if '@' not in email:
            return Response({
                'error': 'Invalid email format',
                'errors': {'email': ['Enter a valid email address.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate CAPACITI email domain
        if not email.endswith('@capaciti.org.za'):
            return Response({
                'error': 'Only CAPACITI email addresses are allowed',
                'errors': {'email': ['Email must be a CAPACITI email address (@capaciti.org.za)']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response({
                'error': 'User with this email already exists',
                'errors': {'email': ['A user with this email already exists.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create superuser
            user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role='superuser'
            )

            user_data = UserSerializer(user).data

            return Response({
                'message': 'Superuser created successfully',
                'user': user_data
            }, status=status.HTTP_201_CREATED)

        except Exception:
            return Response({
                'error': 'Failed to create superuser'
            }, status=status.HTTP_400_BAD_REQUEST)