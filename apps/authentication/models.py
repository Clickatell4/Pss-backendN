"""
SCRUM-117: Password Reset Models
Secure token-based password reset with expiry and rate limiting
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
import secrets
import hashlib

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
