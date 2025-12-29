from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from datetime import datetime, date, timedelta
from encrypted_model_fields.fields import EncryptedCharField, EncryptedTextField
from auditlog.registry import auditlog

class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        # SCRUM-9: Validate password strength before setting
        if password:
            validate_password(password, user)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self._create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('candidate', 'Candidate'),
        ('admin', 'Admin'),
        ('superuser', 'Superuser'),
    ]
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='candidate')
    has_completed_intake = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # SCRUM-9: Password expiry tracking (90-day policy)
    password_last_changed = models.DateTimeField(default=timezone.now)

    # SCRUM-14: Two-Factor Authentication
    totp_secret = EncryptedCharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Encrypted TOTP secret (base32)"
    )
    totp_enabled = models.BooleanField(
        default=False,
        help_text="Whether 2FA is enabled for this user"
    )
    totp_enabled_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When 2FA was enabled"
    )
    totp_last_used = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last successful 2FA verification"
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def clean(self):
        super().clean()
        if self.email and not self.email.endswith('@capaciti.org.za'):
            raise ValidationError('Email must be a CAPACITI email address')

    def is_password_expired(self):
        """
        Check if password has expired (90 days old).

        Returns:
            bool: True if password is expired, False otherwise
        """
        expiry_date = self.password_last_changed + timedelta(days=90)
        return timezone.now() > expiry_date

    def save(self, *args, **kwargs):
        self.clean()

        # SCRUM-9: Track password changes and prevent reuse
        if self.pk:  # Existing user
            try:
                old_user = User.objects.get(pk=self.pk)

                # Check if password changed
                if old_user.password != self.password:
                    # Check against password history (prevent reuse)
                    from .popia_models import PasswordHistory  # Import here to avoid circular import
                    history = PasswordHistory.objects.filter(user=self).order_by('-created_at')[:5]

                    for hist in history:
                        if self.check_password(hist.password_hash):
                            raise ValidationError(
                                'Cannot reuse your last 5 passwords. Please choose a different password.'
                            )

                    # Save old password to history
                    PasswordHistory.objects.create(
                        user=self,
                        password_hash=old_user.password  # Store hashed password
                    )

                    # Keep only last 5 passwords in history
                    old_passwords = PasswordHistory.objects.filter(user=self).order_by('-created_at')[5:]
                    for old_pass in old_passwords:
                        old_pass.delete()

                    # Update password change timestamp
                    self.password_last_changed = timezone.now()

            except User.DoesNotExist:
                pass  # New user, no history to check

        super().save(*args, **kwargs)

    def __str__(self):
        return self.email

class UserProfile(models.Model):
    """
    User profile containing sensitive PII data.

    POPIA Compliance: The following fields are encrypted at rest:
    - id_number (SA ID contains DOB, gender)
    - Medical information (diagnosis, medications, allergies, medical_notes)
    - Doctor information (doctor_name, doctor_phone)
    - Emergency contacts (emergency_contact, emergency_phone)

    SCRUM-118: Data Minimization
    - Removed date_of_birth field (redundant with id_number)
    - DOB can be calculated from SA ID number using date_of_birth_calculated property
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')

    # Encrypted PII fields - SA ID number
    id_number = EncryptedCharField(max_length=255, null=True, blank=True)

    # Contact information
    contact_number = models.CharField(max_length=15, null=True, blank=True)
    address = models.TextField(null=True, blank=True)

    # Encrypted emergency contact information
    emergency_contact = EncryptedCharField(max_length=255, null=True, blank=True)
    emergency_phone = EncryptedCharField(max_length=255, null=True, blank=True)

    # Encrypted medical information (highly sensitive)
    diagnosis = EncryptedTextField(null=True, blank=True)
    medications = EncryptedTextField(null=True, blank=True)
    allergies = EncryptedTextField(null=True, blank=True)
    medical_notes = EncryptedTextField(null=True, blank=True)

    # Encrypted doctor information
    doctor_name = EncryptedCharField(max_length=255, null=True, blank=True)
    doctor_phone = EncryptedCharField(max_length=255, null=True, blank=True)

    # Non-sensitive accessibility preferences (not encrypted)
    accommodations = models.TextField(null=True, blank=True)
    assistive_technology = models.TextField(null=True, blank=True)
    learning_style = models.CharField(max_length=100, null=True, blank=True)
    support_needs = models.TextField(null=True, blank=True)
    communication_preferences = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def date_of_birth_calculated(self):
        """
        Calculate date of birth from SA ID number.

        SA ID Format: YYMMDDGSSSCAZ
        - YY: Year (2 digits)
        - MM: Month (01-12)
        - DD: Day (01-31)
        - G: Gender (0-4 female, 5-9 male)
        - SSS: Sequence number
        - C: Citizenship (0=SA, 1=other)
        - A: Usually 8 or 9
        - Z: Checksum digit

        Returns:
            date: Calculated date of birth, or None if id_number is not set
        """
        if not self.id_number:
            return None

        try:
            # Extract date components from ID number (first 6 digits)
            yy = int(self.id_number[:2])
            mm = int(self.id_number[2:4])
            dd = int(self.id_number[4:6])

            # Determine century (assume people are not over 100 years old)
            current_year = datetime.now().year % 100
            year = (1900 + yy) if yy > current_year else (2000 + yy)

            # Validate and return date
            return date(year, mm, dd)
        except (ValueError, IndexError):
            # Invalid ID number format or invalid date
            return None

    @property
    def age_calculated(self):
        """
        Calculate age from date of birth (derived from ID number).

        Returns:
            int: Age in years, or None if DOB cannot be determined
        """
        dob = self.date_of_birth_calculated
        if not dob:
            return None

        today = date.today()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        return age

    def __str__(self):
        return f"profile: {self.user.email}"


# =============================================================================
# SCRUM-119: Inactive Account Deletion Scheduling
# =============================================================================

class AccountDeletionSchedule(models.Model):
    """
    Tracks accounts scheduled for deletion due to inactivity.

    POPIA Section 14: Retention and Restriction of Records
    - Accounts inactive for 2+ years are scheduled for deletion
    - 30-day grace period with email warnings
    - Login during grace period cancels deletion
    - Admin accounts are exempt from auto-deletion
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='deletion_schedule')
    scheduled_deletion_date = models.DateTimeField(
        help_text="Date when account will be permanently deleted"
    )
    first_warning_sent = models.DateTimeField(null=True, blank=True)
    second_warning_sent = models.DateTimeField(null=True, blank=True)
    exempted = models.BooleanField(
        default=False,
        help_text="If True, account is exempt from automatic deletion (admin override)"
    )
    exemption_reason = models.TextField(
        blank=True,
        help_text="Reason for exemption from automatic deletion"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['scheduled_deletion_date']
        indexes = [
            models.Index(fields=['scheduled_deletion_date', 'exempted']),
        ]

    def __str__(self):
        status = "EXEMPTED" if self.exempted else f"scheduled for {self.scheduled_deletion_date.date()}"
        return f"{self.user.email} - {status}"

    @property
    def days_until_deletion(self):
        """Calculate days remaining until deletion."""
        if self.exempted:
            return None
        delta = self.scheduled_deletion_date - timezone.now()
        return max(0, delta.days)

    @property
    def is_overdue(self):
        """Check if deletion date has passed."""
        if self.exempted:
            return False
        return timezone.now() > self.scheduled_deletion_date


# =============================================================================
# SCRUM-8: Register models for audit logging (POPIA compliance)
# =============================================================================
# Tracks all changes to User and UserProfile for compliance and security monitoring
auditlog.register(User, exclude_fields=['password', 'last_login'])  # Don't log sensitive password data
auditlog.register(UserProfile)  # Track all PII changes

# =============================================================================
# SCRUM-11: Import POPIA compliance models
# =============================================================================
# Import after User model is defined to avoid circular imports
from .popia_models import (  # noqa: E402, F401
    PrivacyPolicyVersion,
    UserConsent,
    DataDeletionRequest,
    DataExportRequest
)
