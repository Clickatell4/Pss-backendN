"""
SCRUM-117: Password Reset Models
SCRUM-30: Session Management Models
Secure token-based password reset with expiry and rate limiting
Session tracking with device metadata and activity monitoring
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
import secrets
import hashlib

try:
    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
except ImportError:
    OutstandingToken = None
    BlacklistedToken = None

User = get_user_model()


class PasswordResetToken(models.Model):
    """
    Stores password reset tokens with security features:
    - Tokens are hashed (not stored in plaintext)
    - 1-hour expiry
    - Single-use (invalidated after use)
    - Rate limiting via created_at tracking
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token_hash = models.CharField(max_length=128, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token_hash', 'used', 'expires_at']),
        ]

    @classmethod
    def generate_token(cls, user, ip_address=None, user_agent=None):
        """
        Generate a secure random token for password reset.

        Args:
            user: User requesting password reset
            ip_address: IP address of requester (for audit trail)
            user_agent: User agent of requester (for audit trail)

        Returns:
            tuple: (token_string, PasswordResetToken instance)
        """
        # Generate cryptographically secure random token
        token_string = secrets.token_urlsafe(32)  # 32 bytes = 256 bits

        # Hash the token before storing (prevent plaintext exposure)
        token_hash = hashlib.sha256(token_string.encode()).hexdigest()

        # Create token with 1-hour expiry
        expires_at = timezone.now() + timedelta(hours=1)

        reset_token = cls.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )

        return token_string, reset_token

    @classmethod
    def verify_token(cls, token_string):
        """
        Verify a password reset token.

        Args:
            token_string: The token provided by the user

        Returns:
            PasswordResetToken instance if valid, None otherwise

        Validation checks:
            - Token exists (hash matches)
            - Not expired
            - Not already used
        """
        # Hash the provided token
        token_hash = hashlib.sha256(token_string.encode()).hexdigest()

        try:
            reset_token = cls.objects.get(
                token_hash=token_hash,
                used=False,
                expires_at__gt=timezone.now()
            )
            return reset_token
        except cls.DoesNotExist:
            return None

    def mark_as_used(self):
        """Mark token as used to prevent reuse."""
        self.used = True
        self.used_at = timezone.now()
        self.save(update_fields=['used', 'used_at'])

    def is_valid(self):
        """Check if token is still valid (not expired, not used)."""
        return (
            not self.used and
            self.expires_at > timezone.now()
        )

    def __str__(self):
        status = "used" if self.used else ("expired" if self.expires_at < timezone.now() else "valid")
        return f"PasswordResetToken for {self.user.email} ({status})"


class UserSession(models.Model):
    """
    SCRUM-30: Tracks active JWT sessions with device and location metadata.

    Integrates with SimpleJWT's OutstandingToken to provide:
    - Device identification (mobile, desktop, tablet, bot)
    - Browser and OS tracking
    - IP address and optional geolocation
    - Activity monitoring (last_activity timestamp)
    - Suspicious login detection
    - Session termination capabilities

    Security features:
    - session_key is SHA256 hash of token jti (not the actual token)
    - Linked to OutstandingToken for automatic blacklisting
    - IP address tracking for security monitoring
    - Suspicious login flagging for new devices/IPs
    """

    # Device type choices
    DEVICE_MOBILE = 'mobile'
    DEVICE_TABLET = 'tablet'
    DEVICE_PC = 'pc'
    DEVICE_BOT = 'bot'
    DEVICE_UNKNOWN = 'unknown'

    DEVICE_TYPE_CHOICES = [
        (DEVICE_MOBILE, 'Mobile'),
        (DEVICE_TABLET, 'Tablet'),
        (DEVICE_PC, 'PC'),
        (DEVICE_BOT, 'Bot'),
        (DEVICE_UNKNOWN, 'Unknown'),
    ]

    # Core relationships
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions'
    )
    outstanding_token = models.OneToOneField(
        'token_blacklist.OutstandingToken',
        on_delete=models.CASCADE,
        related_name='session',
        null=True,
        blank=True
    )

    # Session identification
    session_key = models.CharField(
        max_length=128,
        unique=True,
        db_index=True,
        help_text="SHA256 hash of token jti for identification"
    )

    # Device metadata
    device_type = models.CharField(
        max_length=20,
        choices=DEVICE_TYPE_CHOICES,
        default=DEVICE_UNKNOWN
    )
    browser = models.CharField(max_length=100, blank=True)
    os = models.CharField(max_length=100, blank=True, verbose_name="Operating System")
    user_agent = models.CharField(max_length=500, blank=True)

    # Location metadata (optional)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_activity = models.DateTimeField(auto_now_add=True, db_index=True)
    expires_at = models.DateTimeField(db_index=True)

    # Security flags
    is_suspicious = models.BooleanField(
        default=False,
        help_text="Flagged if login from new device/IP"
    )
    terminated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user', 'is_suspicious']),
            models.Index(fields=['user', 'last_activity']),
            models.Index(fields=['session_key', 'terminated_at']),
            models.Index(fields=['expires_at', 'terminated_at']),
        ]
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'

    @property
    def is_active(self):
        """Check if session is currently active (not terminated, not expired)."""
        if self.terminated_at:
            return False
        return timezone.now() < self.expires_at

    @property
    def is_expired(self):
        """Check if session has expired."""
        return timezone.now() >= self.expires_at

    def terminate(self):
        """
        Terminate this session by blacklisting the refresh token.
        This prevents the token from being used to refresh access tokens.
        """
        if self.terminated_at:
            return  # Already terminated

        self.terminated_at = timezone.now()
        self.save(update_fields=['terminated_at'])

        # Blacklist the outstanding token if available
        if self.outstanding_token and BlacklistedToken:
            try:
                BlacklistedToken.objects.get_or_create(token=self.outstanding_token)
            except Exception:
                pass  # Silent fail if blacklisting fails

    def mark_suspicious(self, save=True):
        """Mark this session as suspicious."""
        self.is_suspicious = True
        if save:
            self.save(update_fields=['is_suspicious'])

    def update_activity(self):
        """Update last_activity timestamp."""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])

    @classmethod
    def create_session(cls, user, outstanding_token, session_key, device_type='unknown',
                       browser='', os='', user_agent='', ip_address=None,
                       country='', city='', is_suspicious=False):
        """
        Create a new user session.

        Args:
            user: User instance
            outstanding_token: OutstandingToken instance from SimpleJWT
            session_key: SHA256 hash of token jti
            device_type: Type of device (mobile, tablet, pc, bot, unknown)
            browser: Browser name
            os: Operating system name
            user_agent: Full user agent string
            ip_address: IP address of the request
            country: Country name (optional)
            city: City name (optional)
            is_suspicious: Whether this login is suspicious

        Returns:
            UserSession instance
        """
        # Calculate expiry (same as refresh token - 7 days)
        expires_at = outstanding_token.expires_at if outstanding_token else timezone.now() + timedelta(days=7)

        return cls.objects.create(
            user=user,
            outstanding_token=outstanding_token,
            session_key=session_key,
            device_type=device_type,
            browser=browser,
            os=os,
            user_agent=user_agent,
            ip_address=ip_address,
            country=country,
            city=city,
            expires_at=expires_at,
            is_suspicious=is_suspicious
        )

    def __str__(self):
        status = "terminated" if self.terminated_at else ("expired" if self.is_expired else "active")
        return f"{self.user.email} - {self.device_type} ({status})"


# =============================================================================
# SCRUM-14: Two-Factor Authentication Backup Codes
# =============================================================================

class TwoFactorBackupCode(models.Model):
    """
    SCRUM-14: Backup codes for 2FA recovery

    Backup codes allow users to login when they don't have access to their
    authenticator app. Each code is single-use and hashed like a password.

    Security:
    - Codes are hashed with SHA256 (irreversible, like passwords)
    - Each code can only be used once
    - Format: XXXX-XXXX (8 characters, easy to type)
    - 10 codes generated per user by default
    """
    user = models.ForeignKey(
        'users.User',
        on_delete=models.CASCADE,
        related_name='backup_codes',
        help_text="User who owns this backup code"
    )
    code_hash = models.CharField(
        max_length=128,
        db_index=True,
        help_text="SHA256 hash of backup code"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="When this code was generated"
    )
    used = models.BooleanField(
        default=False,
        help_text="Whether this code has been used"
    )
    used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this code was used"
    )

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'used']),
        ]

    @classmethod
    def generate_codes(cls, user, count=10):
        """
        Generate backup codes for user.

        Args:
            user: User instance
            count: Number of codes to generate (default: 10)

        Returns:
            list: Plaintext backup codes in format XXXX-XXXX
                  (shown once, never stored in plaintext)
        """
        import hashlib
        import secrets
        import string

        # Delete existing codes
        cls.objects.filter(user=user).delete()

        codes = []
        for _ in range(count):
            # Generate random 8-character code (alphanumeric)
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            # Format as XXXX-XXXX for readability
            formatted_code = f"{code[:4]}-{code[4:]}"

            # Hash the code (SHA256)
            code_hash = hashlib.sha256(formatted_code.encode()).hexdigest()

            # Save to database
            cls.objects.create(
                user=user,
                code_hash=code_hash
            )

            # Add to return list (plaintext, shown only once)
            codes.append(formatted_code)

        return codes

    @classmethod
    def verify_code(cls, user, code):
        """
        Verify backup code and mark as used.

        Args:
            user: User instance
            code: Plaintext backup code

        Returns:
            bool: True if code is valid and unused, False otherwise
        """
        import hashlib

        # Normalize code (remove spaces, convert to uppercase)
        normalized_code = code.strip().upper().replace(' ', '')

        # Add hyphen if missing (user might enter without hyphen)
        if len(normalized_code) == 8 and '-' not in normalized_code:
            normalized_code = f"{normalized_code[:4]}-{normalized_code[4:]}"

        # Hash the code
        code_hash = hashlib.sha256(normalized_code.encode()).hexdigest()

        # Find matching unused code
        try:
            backup_code = cls.objects.get(
                user=user,
                code_hash=code_hash,
                used=False
            )
            # Mark as used
            backup_code.mark_as_used()
            return True
        except cls.DoesNotExist:
            return False

    def mark_as_used(self):
        """Mark this backup code as used."""
        self.used = True
        self.used_at = timezone.now()
        self.save(update_fields=['used', 'used_at'])

    def __str__(self):
        status = "USED" if self.used else "UNUSED"
        return f"{self.user.email} - Backup Code ({status})"


# SCRUM-8: Register models with auditlog for POPIA compliance
from auditlog.registry import auditlog

# Register PasswordResetToken for audit trail
auditlog.register(PasswordResetToken)

# Register UserSession for audit trail (exclude last_activity to reduce noise)
auditlog.register(UserSession, exclude_fields=['last_activity'])

# SCRUM-14: Register TwoFactorBackupCode for audit trail
auditlog.register(TwoFactorBackupCode)
