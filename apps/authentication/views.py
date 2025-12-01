from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from apps.users.serializers import UserSerializer
from apps.users.permissions import IsSuperuser, IsAdminOrSuperuser
from pss_backend.throttles import (
    AuthRateThrottle,
    RegisterRateThrottle,
    PasswordResetRequestThrottle,
    PasswordResetConfirmThrottle
)
from pss_backend.validators import sanitize_text, validate_email_domain, validate_text_length
from django.core.exceptions import ValidationError
from apps.authentication.models import PasswordResetToken
import logging

User = get_user_model()
logger = logging.getLogger('django.security.auth')

class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthRateThrottle]  # SCRUM-10: Rate limit login attempts

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

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

        try:
            user = authenticate(request, username=email, password=password)

            if user is not None:
                if not user.is_active:
                    return Response({
                        'detail': 'Account is deactivated'
                    }, status=status.HTTP_401_UNAUTHORIZED)

                refresh = RefreshToken.for_user(user)
                user_data = UserSerializer(user).data
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': user_data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'detail': 'Invalid email or password'
                }, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
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


# =============================================================================
# PASSWORD RESET VIEWS (SCRUM-117)
# =============================================================================

class PasswordResetRequestView(APIView):
    """
    Request a password reset token.

    Rate Limited: 3 attempts per hour per IP (prevents email bombing)
    Security: Doesn't reveal if email exists (prevents enumeration)
    """
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetRequestThrottle]

    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({
                'detail': 'Email is required',
                'errors': {'email': ['This field is required.']}
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

        # Get IP and user agent for audit trail
        ip_address = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]

        # SECURITY: Always return success to prevent email enumeration
        # Only send email if user actually exists
        try:
            user = User.objects.get(email=email, is_active=True)

            # Generate reset token
            token_string, reset_token = PasswordResetToken.generate_token(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent
            )

            # Send password reset email
            self._send_reset_email(user, token_string)

            # Log the request
            logger.info(
                f"Password reset requested for {email} from {ip_address}"
            )

        except User.DoesNotExist:
            # User doesn't exist - still return success (prevent enumeration)
            logger.warning(
                f"Password reset requested for non-existent email {email} from {ip_address}"
            )

        # Always return success message (security: don't reveal if email exists)
        return Response({
            'message': 'If an account with that email exists, a password reset link has been sent.',
            'detail': 'Please check your email for instructions.'
        }, status=status.HTTP_200_OK)

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _send_reset_email(self, user, token):
        """Send password reset email to user."""
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"

        subject = 'Password Reset Request - PSS System'
        message = f"""
Hello {user.first_name or user.email},

You have requested to reset your password for the PSS System.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email and your password will remain unchanged.

For security reasons, this link can only be used once.

If you need assistance, please contact support at {settings.DEFAULT_FROM_EMAIL}

---
PSS Support Team
        """.strip()

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            logger.info(f"Password reset email sent to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
            # Don't raise exception - we don't want to reveal email existence


class PasswordResetValidateTokenView(APIView):
    """
    Validate a password reset token without consuming it.
    Useful for frontend to check if token is valid before showing form.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('token')

        if not token:
            return Response({
                'valid': False,
                'detail': 'Token is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify token
        reset_token = PasswordResetToken.verify_token(token)

        if reset_token:
            return Response({
                'valid': True,
                'email': reset_token.user.email,
                'detail': 'Token is valid'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'valid': False,
                'detail': 'Token is invalid, expired, or already used'
            }, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    """
    Confirm password reset with token and new password.

    Rate Limited: 5 attempts per 15 minutes (prevents token brute-forcing)
    Security: Token is single-use and expires after 1 hour
    """
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetConfirmThrottle]

    def post(self, request):
        token = request.data.get('token')
        new_password = request.data.get('new_password')

        # Validation
        if not token or not new_password:
            return Response({
                'detail': 'Token and new password are required',
                'errors': {
                    'token': ['This field is required.'] if not token else [],
                    'new_password': ['This field is required.'] if not new_password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate password length (prevent DoS)
        try:
            validate_text_length(new_password, min_length=8, max_length=128, field_name='Password')
        except ValidationError as e:
            return Response({
                'detail': 'Invalid password',
                'errors': {'new_password': [str(e)]}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify token
        reset_token = PasswordResetToken.verify_token(token)

        if not reset_token:
            logger.warning(f"Invalid/expired password reset token attempted from {self._get_client_ip(request)}")
            return Response({
                'detail': 'Invalid, expired, or already used token'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = reset_token.user

        # Validate new password using Django's password validators
        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            return Response({
                'detail': 'Password does not meet requirements',
                'errors': {'new_password': list(e.messages)}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if new password is same as old password
        if user.check_password(new_password):
            return Response({
                'detail': 'New password cannot be the same as your old password',
                'errors': {'new_password': ['Please choose a different password.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # All validations passed - update password
        user.set_password(new_password)
        user.save(update_fields=['password'])

        # Mark token as used
        reset_token.mark_as_used()

        # Log successful password reset
        logger.info(
            f"Password reset successful for {user.email} from {self._get_client_ip(request)}"
        )

        # Invalidate all existing sessions/tokens (optional - security best practice)
        # This forces user to log in with new password
        try:
            # Blacklist all refresh tokens
            OutstandingToken.objects.filter(user=user).delete()
        except Exception as e:
            logger.warning(f"Failed to invalidate tokens for {user.email}: {str(e)}")

        return Response({
            'message': 'Password has been reset successfully',
            'detail': 'You can now log in with your new password'
        }, status=status.HTTP_200_OK)

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip