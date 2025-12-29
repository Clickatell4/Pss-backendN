"""
SCRUM-117: Password Reset and Change Serializers
SCRUM-30: Session Management Serializers
Handles validation for password reset, confirmation, and password change operations
Provides serialization for user session data and admin session management
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta

User = get_user_model()


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request endpoint.
    Only requires email address (validation happens in view).
    """
    email = serializers.EmailField(required=True)


class PasswordResetValidateTokenSerializer(serializers.Serializer):
    """
    Serializer for password reset token validation.
    Frontend uses this to check if token is valid before showing reset form.
    """
    token = serializers.CharField(required=True)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation.
    Validates token and new password.
    """
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        max_length=128
    )


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for authenticated user password change.
    Requires old password (for verification) and new password.
    
    Security:
    - Old password must be correct (prevents account takeover if session hijacked)
    - New password goes through Django's password validators
    - Cannot be same as old password
    """
    old_password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=1,
        max_length=128
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        max_length=128
    )
    
    def validate_old_password(self, value):
        """Verify old password is correct"""
        user = self.context.get('user')
        if not user:
            raise ValidationError("User not found in context")
        
        if not user.check_password(value):
            raise ValidationError("Old password is incorrect")
        
        return value
    
    def validate_new_password(self, value):
        """
        Validate new password against Django's validators.
        This checks:
        - Minimum length requirements
        - Common password list
        - Numeric-only passwords
        - Too similar to user info
        """
        user = self.context.get('user')
        if user:
            try:
                validate_password(value, user=user)
            except ValidationError as e:
                raise ValidationError(list(e.messages))
        return value
    
    def validate(self, data):
        """Cross-field validation"""
        old_password = data.get('old_password')
        new_password = data.get('new_password')

        user = self.context.get('user')

        # Check if new password is same as old password
        if user and user.check_password(new_password):
            raise ValidationError({
                'new_password': 'New password cannot be the same as your old password'
            })

        return data


# SCRUM-30: Session Management Serializers

class UserSessionSerializer(serializers.Serializer):
    """
    Serializer for user session data.

    Provides read-only view of session information including:
    - Device metadata (type, browser, OS)
    - Location (IP address, optional country/city)
    - Timestamps (created, last activity, expiry)
    - Status flags (active, expired, current, suspicious)

    All fields are read-only - sessions cannot be modified via API,
    only viewed or terminated (deletion).
    """

    id = serializers.IntegerField(read_only=True)
    session_key = serializers.CharField(read_only=True)

    # Device metadata
    device_type = serializers.CharField(read_only=True)
    browser = serializers.CharField(read_only=True)
    os = serializers.CharField(read_only=True)
    user_agent = serializers.CharField(read_only=True)

    # Location metadata
    ip_address = serializers.IPAddressField(read_only=True)
    country = serializers.CharField(read_only=True)
    city = serializers.CharField(read_only=True)

    # Timestamps
    created_at = serializers.DateTimeField(read_only=True)
    last_activity = serializers.DateTimeField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True)

    # Status flags
    is_active = serializers.BooleanField(read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    is_suspicious = serializers.BooleanField(read_only=True)

    # Computed fields
    is_current = serializers.SerializerMethodField()
    time_since_activity = serializers.SerializerMethodField()

    def get_is_current(self, obj):
        """
        Determine if this is the current session making the request.

        Note: This is an approximation - we can't perfectly identify the current
        session from the access token alone. We mark the most recently active
        session as current.
        """
        # Check if this session is marked as current in context
        current_session_id = self.context.get('current_session_id')
        if current_session_id:
            return obj.id == current_session_id
        return False

    def get_time_since_activity(self, obj):
        """
        Get human-readable time since last activity.
        Examples: "5 minutes ago", "2 hours ago", "3 days ago"
        """
        if not obj.last_activity:
            return "Never"

        now = timezone.now()
        delta = now - obj.last_activity

        # Calculate time units
        seconds = int(delta.total_seconds())
        minutes = seconds // 60
        hours = minutes // 60
        days = hours // 24

        # Return human-readable format
        if seconds < 60:
            return "Just now"
        elif minutes < 60:
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif hours < 24:
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        else:
            return f"{days} day{'s' if days != 1 else ''} ago"


class AdminUserSessionSerializer(UserSessionSerializer):
    """
    Extended serializer for admin session management.

    Includes additional user information that admins need to see:
    - User email
    - User role (superuser, admin, candidate)

    Only accessible by admin/superuser users.
    """

    user_email = serializers.SerializerMethodField()
    user_role = serializers.SerializerMethodField()

    def get_user_email(self, obj):
        """Get the email of the user who owns this session."""
        return obj.user.email if obj.user else None

    def get_user_role(self, obj):
        """
        Get the role of the user who owns this session.
        Returns: 'superuser', 'admin', or 'candidate'
        """
        if not obj.user:
            return None

        if obj.user.is_superuser:
            return 'superuser'
        elif obj.user.role == 'admin':
            return 'admin'
        else:
            return 'candidate'


# =============================================================================
# SCRUM-14: Two-Factor Authentication Serializers
# =============================================================================

class TwoFactorSetupSerializer(serializers.Serializer):
    """
    Serializer for initiating 2FA setup.

    No input fields required - uses authenticated user from context.

    Returns:
        - secret: Base32-encoded TOTP secret (for manual entry)
        - qr_code_base64: Base64-encoded QR code image
        - provisioning_uri: otpauth:// URI for manual setup
        - issuer: Service name shown in authenticator app
    """
    # Output fields only (read-only)
    secret = serializers.CharField(read_only=True)
    qr_code_base64 = serializers.CharField(read_only=True)
    provisioning_uri = serializers.CharField(read_only=True)
    issuer = serializers.CharField(read_only=True)


class TwoFactorVerifySetupSerializer(serializers.Serializer):
    """
    Serializer for verifying TOTP code during 2FA setup.

    Validates that the user can successfully generate codes with their
    authenticator app before enabling 2FA.

    Input:
        - totp_code: 6-digit code from authenticator app

    Returns:
        - backup_codes: List of 10 single-use backup codes (ONLY TIME SHOWN)
        - message: Success message
    """
    totp_code = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text="6-digit TOTP code from authenticator app"
    )

    def validate_totp_code(self, value):
        """Validate TOTP code format"""
        if not value.isdigit():
            raise ValidationError("TOTP code must contain only digits")
        return value


class TwoFactorDisableSerializer(serializers.Serializer):
    """
    Serializer for disabling 2FA.

    Requires password confirmation for security (prevents account takeover
    if session is hijacked).

    Input:
        - password: User's current password (required)

    Security:
        - Admin/superuser roles cannot disable 2FA (mandatory enforcement)
        - Password must be correct
        - All backup codes deleted on disable
    """
    password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=1,
        max_length=128,
        help_text="Current password for confirmation"
    )

    def validate_password(self, value):
        """Verify password is correct"""
        user = self.context.get('user')
        if not user:
            raise ValidationError("User not found in context")

        if not user.check_password(value):
            raise ValidationError("Password is incorrect")

        return value

    def validate(self, data):
        """Check if user is allowed to disable 2FA"""
        user = self.context.get('user')

        # Prevent admin/superuser from disabling 2FA (mandatory policy)
        if user and user.role in ['admin', 'superuser']:
            raise ValidationError({
                'non_field_errors': '2FA is mandatory for admin and superuser accounts and cannot be disabled'
            })

        return data


class TwoFactorVerifyCodeSerializer(serializers.Serializer):
    """
    Serializer for verifying TOTP or backup code during login.

    Used in the second step of login flow after password authentication.

    Input:
        - email: User's email address
        - code: Either 6-digit TOTP code OR 8-character backup code (XXXX-XXXX)

    Returns:
        - access: JWT access token (1 hour)
        - refresh: JWT refresh token (7 days)
        - user: User data (email, role, etc.)

    Security:
        - User must have passed password authentication first
        - user_id temporarily stored in cache (5 min timeout)
        - Backup codes are single-use
        - TOTP codes have time window (±30 seconds)
    """
    email = serializers.EmailField(
        required=True,
        help_text="User's email address"
    )
    code = serializers.CharField(
        required=True,
        min_length=6,
        max_length=9,  # Either 6-digit TOTP or 8-char + hyphen backup code
        help_text="6-digit TOTP code or 8-character backup code (XXXX-XXXX)"
    )

    def validate_code(self, value):
        """Normalize code (remove spaces, uppercase for backup codes)"""
        normalized = value.strip().upper().replace(' ', '')

        # Validate format (6 digits OR 8-9 alphanumeric with optional hyphen)
        if len(normalized) == 6 and normalized.isdigit():
            # TOTP code
            return normalized
        elif len(normalized) in [8, 9]:
            # Backup code (with or without hyphen)
            return normalized
        else:
            raise ValidationError(
                "Code must be either a 6-digit TOTP code or an 8-character backup code (XXXX-XXXX)"
            )


class BackupCodesRegenerateSerializer(serializers.Serializer):
    """
    Serializer for regenerating backup codes.

    Requires password confirmation for security.

    Input:
        - password: User's current password (required)

    Returns:
        - backup_codes: List of 10 new backup codes (ONLY TIME SHOWN)
        - count: Number of codes generated

    Security:
        - Password must be correct
        - All old backup codes are deleted
        - New codes shown only once
        - 2FA must be enabled
    """
    password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=1,
        max_length=128,
        help_text="Current password for confirmation"
    )

    def validate_password(self, value):
        """Verify password is correct"""
        user = self.context.get('user')
        if not user:
            raise ValidationError("User not found in context")

        if not user.check_password(value):
            raise ValidationError("Password is incorrect")

        return value

    def validate(self, data):
        """Check if 2FA is enabled"""
        user = self.context.get('user')

        if user and not user.totp_enabled:
            raise ValidationError({
                'non_field_errors': '2FA must be enabled to regenerate backup codes'
            })

        return data
