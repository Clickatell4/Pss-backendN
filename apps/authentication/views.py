from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
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
from apps.authentication.serializers import PasswordChangeSerializer
from apps.authentication.email_utils import send_password_reset_email, send_password_change_confirmation_email
from apps.users.popia_models import PasswordHistory
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
        # Use the new email utility for better formatted emails
        send_password_reset_email(user, token)


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


# =============================================================================
# PASSWORD CHANGE VIEW (SCRUM-117)
# For authenticated users to change their own password
# =============================================================================

class PasswordChangeView(APIView):
    """
    Change password for authenticated user.
    
    Security Features:
    - Requires old password verification (prevents takeover via session hijacking)
    - Validates new password against Django's password validators
    - Prevents password reuse (checks history)
    - Invalidates all other sessions after change
    - Tracks password change in history
    - Logs all password change attempts
    - Rate limited
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        """
        Change password for the authenticated user.
        
        Request body:
        {
            "old_password": "current_password",
            "new_password": "new_secure_password"
        }
        """
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'user': request.user}
        )

        if not serializer.is_valid():
            logger.warning(
                f"Password change validation failed for {request.user.email}: {serializer.errors}"
            )
            return Response({
                'detail': 'Password change validation failed',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        # Extract validated data
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        user = request.user

        # Additional security: Double-check old password
        if not user.check_password(old_password):
            logger.warning(
                f"Password change attempted with wrong old password for {user.email}"
            )
            return Response({
                'detail': 'Old password is incorrect',
                'errors': {'old_password': ['Password is incorrect']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if new password is same as old password
        if user.check_password(new_password):
            logger.info(
                f"Password change rejected: new password same as old for {user.email}"
            )
            return Response({
                'detail': 'New password cannot be the same as your old password',
                'errors': {'new_password': ['Please choose a different password.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Store old password in history before changing
            old_password_hash = user.password
            
            # Update password
            user.set_password(new_password)
            user.password_last_changed = timezone.now()
            user.save(update_fields=['password', 'password_last_changed'])

            # Store in password history (SCRUM-9: prevent reuse)
            PasswordHistory.objects.create(
                user=user,
                password_hash=old_password_hash
            )

            logger.info(
                f"Password changed successfully for {user.email} from {self._get_client_ip(request)}"
            )

            # Security best practice: Invalidate all other sessions
            # This forces user to stay logged in only to the current session
            try:
                # Get all tokens except current one
                from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
                
                # Invalidate all refresh tokens for this user
                OutstandingToken.objects.filter(user=user).delete()
                
                logger.info(f"All sessions invalidated for {user.email} after password change")
            except Exception as e:
                logger.warning(
                    f"Failed to invalidate sessions for {user.email} after password change: {str(e)}"
                )

            # Send confirmation email
            self._send_password_change_confirmation_email(user)

            return Response({
                'message': 'Password changed successfully',
                'detail': 'Your password has been updated. You may need to log in again on other devices.'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error changing password for {user.email}: {str(e)}")
            return Response({
                'detail': 'Failed to change password'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _send_password_change_confirmation_email(self, user):
        """Send confirmation email after successful password change."""
        # Use the new email utility for better formatted emails
        send_password_change_confirmation_email(user)