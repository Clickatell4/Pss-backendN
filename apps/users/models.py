from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import datetime, date
from encrypted_model_fields.fields import EncryptedCharField, EncryptedTextField
from auditlog.registry import auditlog

class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
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

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def clean(self):
        super().clean()
        if self.email and not self.email.endswith('@capaciti.org.za'):
            raise ValidationError('Email must be a CAPACITI email address')

    def save(self, *args, **kwargs):
        self.clean()
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
