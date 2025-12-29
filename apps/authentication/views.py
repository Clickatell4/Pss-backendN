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
from apps.authentication.models import PasswordResetToken, UserSession
from apps.authentication.serializers import (
    PasswordChangeSerializer,
    UserSessionSerializer,
    AdminUserSessionSerializer
)
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

                # SCRUM-14: Check if 2FA is enabled
                if user.totp_enabled:
                    # Store user_id in cache for 5 minutes
                    from django.core.cache import cache
                    cache_key = f'2fa_pending_{user.email}'
                    cache.set(cache_key, user.id, timeout=300)  # 5 minutes

                    logger.info(f"2FA REQUIRED | User: {user.email} | IP: {get_client_ip(request)}")

                    return Response({
                        'requires_2fa': True,
                        'email': user.email,
                        'message': 'Please enter your 2FA authentication code'
                    }, status=status.HTTP_200_OK)

                # SCRUM-14: Check if 2FA is mandatory but not enabled (admin/superuser)
                if user.role in ['admin', 'superuser'] and not user.totp_enabled:
                    logger.warning(
                        f"2FA SETUP REQUIRED | User: {user.email} | Role: {user.role} | "
                        f"IP: {get_client_ip(request)}"
                    )

                    return Response({
                        'requires_2fa_setup': True,
                        'message': '2FA is mandatory for admin and superuser accounts. Please set up 2FA to continue.',
                        'setup_url': '/auth/2fa/setup/'
                    }, status=status.HTTP_403_FORBIDDEN)

                # No 2FA required - proceed with normal login
                refresh = RefreshToken.for_user(user)

                # SCRUM-30: Attach request context for session signal
                try:
                    outstanding_token = OutstandingToken.objects.filter(
                        user=user,
                        token=str(refresh)
                    ).latest('created_at')

                    # Temporarily attach request context for signal handler
                    outstanding_token._request_context = request
                    outstanding_token.save()
                except OutstandingToken.DoesNotExist:
                    # If token doesn't exist, session won't be created (logged in signal)
                    pass
                except Exception as e:
                    # Don't break login if session creation fails
                    logger.warning(f"Failed to attach request context for session: {str(e)}")

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


# SCRUM-30: Session Management Views

class SessionListView(APIView):
    """
    GET /auth/sessions/

    List all active sessions for the authenticated user.
    Shows device info, location, activity timestamps, and flags current session.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def get(self, request):
        """List all sessions for the current user."""
        try:
            # Get all active sessions for the user
            sessions = UserSession.objects.filter(
                user=request.user,
                terminated_at__isnull=True
            ).order_by('-last_activity')

            # Mark the current session (most recently active)
            current_session = sessions.first()
            current_session_id = current_session.id if current_session else None

            # Serialize sessions
            serializer = UserSessionSerializer(
                sessions,
                many=True,
                context={'current_session_id': current_session_id}
            )

            return Response({
                'sessions': serializer.data,
                'count': sessions.count()
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error listing sessions for {request.user.email}: {str(e)}")
            return Response({
                'detail': 'Failed to retrieve sessions'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SessionDeleteView(APIView):
    """
    DELETE /auth/sessions/{session_key}/

    Terminate a specific session. User can only delete their own sessions.
    Cannot delete current session (use /auth/logout/ instead).
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def delete(self, request, session_key):
        """Delete a specific session."""
        try:
            # Get the session
            session = UserSession.objects.filter(
                session_key=session_key,
                user=request.user,
                terminated_at__isnull=True
            ).first()

            if not session:
                return Response({
                    'detail': 'Session not found'
                }, status=status.HTTP_404_NOT_FOUND)

            # Prevent deleting current session
            # The current session is the most recently active one
            current_session = UserSession.objects.filter(
                user=request.user,
                terminated_at__isnull=True
            ).order_by('-last_activity').first()

            if current_session and session.id == current_session.id:
                return Response({
                    'detail': 'Cannot delete current session. Use /auth/logout/ to logout.'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Terminate the session
            session.terminate()

            logger.info(
                f"Session terminated | User: {request.user.email} | "
                f"Device: {session.device_type} | Session: {session_key[:16]}..."
            )

            return Response({
                'message': 'Session terminated successfully',
                'device': session.device_type,
                'browser': session.browser
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error deleting session for {request.user.email}: {str(e)}")
            return Response({
                'detail': 'Failed to delete session'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SessionDeleteAllView(APIView):
    """
    DELETE /auth/sessions/all/

    Terminate ALL sessions for the authenticated user, including current session.
    Useful when user suspects account compromise.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def delete(self, request):
        """Delete all sessions for the current user."""
        try:
            # Get all active sessions
            sessions = UserSession.objects.filter(
                user=request.user,
                terminated_at__isnull=True
            )

            count = sessions.count()

            # Terminate all sessions
            for session in sessions:
                session.terminate()

            logger.warning(
                f"All sessions terminated | User: {request.user.email} | Count: {count}"
            )

            return Response({
                'message': 'All sessions terminated successfully',
                'count': count,
                'detail': 'You have been logged out from all devices.'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error deleting all sessions for {request.user.email}: {str(e)}")
            return Response({
                'detail': 'Failed to delete all sessions'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SessionDeleteAllExceptCurrentView(APIView):
    """
    DELETE /auth/sessions/all-except-current/

    Terminate all OTHER sessions for the user, keeping current session active.
    Useful for "logout from other devices" feature.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def delete(self, request):
        """Delete all sessions except the current one."""
        try:
            # Get all active sessions
            all_sessions = UserSession.objects.filter(
                user=request.user,
                terminated_at__isnull=True
            ).order_by('-last_activity')

            # Current session is the most recently active
            current_session = all_sessions.first()

            if not current_session:
                return Response({
                    'message': 'No sessions to terminate',
                    'count': 0
                }, status=status.HTTP_200_OK)

            # Get sessions to terminate (all except current)
            sessions_to_terminate = all_sessions.exclude(id=current_session.id)

            count = sessions_to_terminate.count()
            terminated_devices = []

            # Terminate sessions
            for session in sessions_to_terminate:
                terminated_devices.append({
                    'device': session.device_type,
                    'browser': session.browser,
                    'last_activity': session.last_activity
                })
                session.terminate()

            logger.info(
                f"Other sessions terminated | User: {request.user.email} | Count: {count}"
            )

            return Response({
                'message': f'Terminated {count} other session(s)',
                'count': count,
                'terminated_devices': terminated_devices
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error deleting other sessions for {request.user.email}: {str(e)}")
            return Response({
                'detail': 'Failed to delete other sessions'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminSessionListView(APIView):
    """
    GET /auth/admin/sessions/

    List all user sessions (admin only).
    Supports filtering by user_email, active_only, suspicious_only.
    """
    permission_classes = [IsAdminOrSuperuser]
    throttle_classes = [AuthRateThrottle]

    def get(self, request):
        """List all sessions with filtering options."""
        try:
            # Start with all sessions
            sessions = UserSession.objects.all()

            # Filter by user email
            user_email = request.query_params.get('user_email')
            if user_email:
                sessions = sessions.filter(user__email__icontains=user_email)

            # Filter by active status
            active_only = request.query_params.get('active_only', '').lower() == 'true'
            if active_only:
                sessions = sessions.filter(
                    terminated_at__isnull=True,
                    expires_at__gt=timezone.now()
                )

            # Filter by suspicious flag
            suspicious_only = request.query_params.get('suspicious_only', '').lower() == 'true'
            if suspicious_only:
                sessions = sessions.filter(is_suspicious=True)

            # Order by most recent activity
            sessions = sessions.order_by('-last_activity')

            # Serialize sessions
            serializer = AdminUserSessionSerializer(sessions, many=True)

            return Response({
                'sessions': serializer.data,
                'count': sessions.count(),
                'filters': {
                    'user_email': user_email,
                    'active_only': active_only,
                    'suspicious_only': suspicious_only
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error listing all sessions (admin): {str(e)}")
            return Response({
                'detail': 'Failed to retrieve sessions'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminForceLogoutView(APIView):
    """
    POST /auth/admin/force-logout/

    Force logout a user by terminating all their sessions (admin only).
    Requires reason for audit compliance.
    Prevents force logout of superusers unless requester is superuser.
    """
    permission_classes = [IsAdminOrSuperuser]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        """Force logout a user."""
        try:
            user_id = request.data.get('user_id')
            reason = request.data.get('reason', '')

            if not user_id:
                return Response({
                    'detail': 'user_id is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            if not reason:
                return Response({
                    'detail': 'reason is required for audit compliance'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get target user
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({
                    'detail': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)

            # Security check: Prevent force logout of superusers unless requester is superuser
            if target_user.is_superuser and not request.user.is_superuser:
                logger.warning(
                    f"Force logout attempt denied | Admin: {request.user.email} | "
                    f"Target: {target_user.email} (superuser)"
                )
                return Response({
                    'detail': 'Cannot force logout a superuser'
                }, status=status.HTTP_403_FORBIDDEN)

            # Get all active sessions
            sessions = UserSession.objects.filter(
                user=target_user,
                terminated_at__isnull=True
            )

            count = sessions.count()

            # Terminate all sessions
            for session in sessions:
                session.terminate()

            # Log admin action with reason (CRITICAL for audit)
            logger.warning(
                f"ADMIN FORCE LOGOUT | Admin: {request.user.email} | "
                f"Target: {target_user.email} | Sessions: {count} | Reason: {reason}"
            )

            return Response({
                'message': f'Force logged out {target_user.email}',
                'sessions_terminated': count,
                'target_user': target_user.email,
                'reason': reason
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error force logging out user: {str(e)}")
            return Response({
                'detail': 'Failed to force logout user'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# =============================================================================
# SCRUM-14: Two-Factor Authentication Views
# =============================================================================

class TwoFactorSetupView(APIView):
    """
    POST /auth/2fa/setup/

    Initiate 2FA setup by generating TOTP secret and QR code.

    Security:
    - Requires authentication (IsAuthenticated)
    - Prevents duplicate setup (if already enabled)
    - Secret temporarily stored in cache (15 min expiry)
    - Rate limited (AuthRateThrottle)

    Returns:
        - secret: Base32-encoded TOTP secret (for manual entry)
        - qr_code_base64: Base64-encoded QR code image
        - provisioning_uri: otpauth:// URI
        - issuer: Service name
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        from django.core.cache import cache
        from .totp_utils import generate_totp_secret, generate_qr_code
        from .serializers import TwoFactorSetupSerializer

        user = request.user

        # Check if 2FA is already enabled
        if user.totp_enabled:
            return Response({
                'detail': '2FA is already enabled for this account'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Generate TOTP secret
        secret = generate_totp_secret()

        # Generate QR code
        qr_data = generate_qr_code(secret, user.email, issuer='PSS Backend')

        # Store secret in cache for 15 minutes (until user verifies)
        cache_key = f'2fa_setup_{user.id}'
        cache.set(cache_key, secret, timeout=900)  # 15 minutes

        # Log setup initiation
        logger.info(f"2FA SETUP INITIATED | User: {user.email} | IP: {get_client_ip(request)}")

        # Serialize and return
        serializer = TwoFactorSetupSerializer(data=qr_data)
        serializer.is_valid(raise_exception=True)

        return Response({
            **serializer.validated_data,
            'issuer': 'PSS Backend',
            'message': 'Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)'
        }, status=status.HTTP_200_OK)


class TwoFactorVerifySetupView(APIView):
    """
    POST /auth/2fa/verify-setup/

    Verify TOTP code and enable 2FA for user.

    Security:
    - Requires authentication
    - Verifies code against cached secret
    - Saves encrypted secret to database
    - Generates 10 single-use backup codes
    - Backup codes shown ONLY ONCE
    - Rate limited

    Input:
        - totp_code: 6-digit code from authenticator app

    Returns:
        - backup_codes: List of 10 backup codes (ONLY TIME SHOWN)
        - message: Success message
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        from django.core.cache import cache
        from .totp_utils import verify_totp_code
        from .serializers import TwoFactorVerifySetupSerializer
        from .models import TwoFactorBackupCode

        user = request.user

        # Validate input
        serializer = TwoFactorVerifySetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        totp_code = serializer.validated_data['totp_code']

        # Get secret from cache
        cache_key = f'2fa_setup_{user.id}'
        secret = cache.get(cache_key)

        if not secret:
            return Response({
                'detail': 'Setup session expired. Please restart 2FA setup.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify TOTP code
        if not verify_totp_code(secret, totp_code):
            return Response({
                'detail': 'Invalid TOTP code. Please try again.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Code is valid - enable 2FA
        from django.utils import timezone

        user.totp_secret = secret  # Encrypted automatically
        user.totp_enabled = True
        user.totp_enabled_at = timezone.now()
        user.save(update_fields=['totp_secret', 'totp_enabled', 'totp_enabled_at'])

        # Generate backup codes
        backup_codes = TwoFactorBackupCode.generate_codes(user, count=10)

        # Clear cache
        cache.delete(cache_key)

        # Log successful setup
        logger.info(f"2FA ENABLED | User: {user.email} | IP: {get_client_ip(request)}")

        return Response({
            'message': '2FA has been successfully enabled for your account',
            'backup_codes': backup_codes,
            'backup_codes_warning': 'Save these backup codes in a secure location. They will not be shown again.'
        }, status=status.HTTP_200_OK)


class TwoFactorDisableView(APIView):
    """
    POST /auth/2fa/disable/

    Disable 2FA for user (candidates only).

    Security:
    - Requires authentication
    - Requires password confirmation
    - Admin/superuser CANNOT disable (mandatory policy)
    - Deletes all backup codes
    - Clears TOTP secret
    - Rate limited

    Input:
        - password: User's current password (required)

    Returns:
        - message: Success message
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        from .serializers import TwoFactorDisableSerializer
        from .models import TwoFactorBackupCode

        user = request.user

        # Validate input (includes password check and role check)
        serializer = TwoFactorDisableSerializer(
            data=request.data,
            context={'user': user}
        )
        serializer.is_valid(raise_exception=True)

        # Check if 2FA is enabled
        if not user.totp_enabled:
            return Response({
                'detail': '2FA is not enabled for this account'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Disable 2FA
        user.totp_secret = None
        user.totp_enabled = False
        user.totp_enabled_at = None
        user.totp_last_used = None
        user.save(update_fields=['totp_secret', 'totp_enabled', 'totp_enabled_at', 'totp_last_used'])

        # Delete all backup codes
        TwoFactorBackupCode.objects.filter(user=user).delete()

        # Log disable action
        logger.warning(f"2FA DISABLED | User: {user.email} | IP: {get_client_ip(request)}")

        return Response({
            'message': '2FA has been disabled for your account'
        }, status=status.HTTP_200_OK)


class TwoFactorVerifyCodeView(APIView):
    """
    POST /auth/2fa/verify-code/

    Verify TOTP or backup code during login (second step).

    Security:
    - Requires prior password authentication (user_id in cache)
    - Verifies either TOTP code OR backup code
    - Backup codes are single-use
    - Issues JWT tokens on success
    - Creates user session (SCRUM-30 integration)
    - Rate limited (5 attempts/15min)

    Input:
        - email: User's email
        - code: 6-digit TOTP OR 8-char backup code (XXXX-XXXX)

    Returns:
        - access: JWT access token (1 hour)
        - refresh: JWT refresh token (7 days)
        - user: User data
    """
    permission_classes = [AllowAny]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        from django.core.cache import cache
        from .totp_utils import verify_totp_code
        from .serializers import TwoFactorVerifyCodeSerializer
        from .models import TwoFactorBackupCode
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
        from apps.users.serializers import UserSerializer

        # Validate input
        serializer = TwoFactorVerifyCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        code = serializer.validated_data['code']

        # Get user_id from cache (set during password authentication)
        cache_key = f'2fa_pending_{email}'
        user_id = cache.get(cache_key)

        if not user_id:
            return Response({
                'detail': '2FA session expired. Please login again with your email and password.'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Get user
        try:
            user = User.objects.get(id=user_id, email=email)
        except User.DoesNotExist:
            return Response({
                'detail': 'Invalid session'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check if 2FA is enabled
        if not user.totp_enabled or not user.totp_secret:
            return Response({
                'detail': '2FA is not properly configured'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Try to verify code (TOTP or backup)
        verified = False
        method = None

        # Check if it's a TOTP code (6 digits)
        if len(code) == 6 and code.isdigit():
            verified = verify_totp_code(user.totp_secret, code)
            method = 'TOTP'
        # Otherwise try as backup code (8-9 chars with optional hyphen)
        else:
            verified = TwoFactorBackupCode.verify_code(user, code)
            method = 'Backup Code'

        if not verified:
            logger.warning(
                f"2FA VERIFICATION FAILED | User: {email} | Method: {method} | "
                f"IP: {get_client_ip(request)}"
            )

            return Response({
                'detail': 'Invalid 2FA code'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Code verified - update last used timestamp
        from django.utils import timezone
        user.totp_last_used = timezone.now()
        user.save(update_fields=['totp_last_used'])

        # Clear cache
        cache.delete(cache_key)

        # Issue JWT tokens
        refresh = RefreshToken.for_user(user)

        # SCRUM-30: Create session (same as LoginView)
        try:
            outstanding_token = OutstandingToken.objects.filter(
                user=user,
                token=str(refresh)
            ).latest('created_at')

            # Attach request context for signal handler
            outstanding_token._request_context = request
            outstanding_token.save()
        except OutstandingToken.DoesNotExist:
            pass
        except Exception as e:
            logger.warning(f"Failed to create session for 2FA login: {str(e)}")

        # Log successful 2FA login
        logger.info(
            f"2FA LOGIN SUCCESS | User: {email} | Method: {method} | "
            f"IP: {get_client_ip(request)}"
        )

        user_data = UserSerializer(user).data

        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': user_data
        }, status=status.HTTP_200_OK)


class BackupCodesRegenerateView(APIView):
    """
    POST /auth/2fa/backup-codes/

    Regenerate backup codes (deletes old ones).

    Security:
    - Requires authentication
    - Requires password confirmation
    - 2FA must be enabled
    - Deletes all old codes
    - Generates 10 new codes
    - Codes shown ONLY ONCE
    - Rate limited

    Input:
        - password: User's current password (required)

    Returns:
        - backup_codes: List of 10 new backup codes
        - count: Number of codes generated
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        from .serializers import BackupCodesRegenerateSerializer
        from .models import TwoFactorBackupCode

        user = request.user

        # Validate input (includes password check and 2FA enabled check)
        serializer = BackupCodesRegenerateSerializer(
            data=request.data,
            context={'user': user}
        )
        serializer.is_valid(raise_exception=True)

        # Generate new backup codes (deletes old ones automatically)
        backup_codes = TwoFactorBackupCode.generate_codes(user, count=10)

        # Log regeneration
        logger.info(f"BACKUP CODES REGENERATED | User: {user.email} | IP: {get_client_ip(request)}")

        return Response({
            'message': 'Backup codes have been regenerated',
            'backup_codes': backup_codes,
            'count': len(backup_codes),
            'warning': 'Save these backup codes in a secure location. They will not be shown again.'
        }, status=status.HTTP_200_OK)