from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from encrypted_model_fields.fields import EncryptedCharField, EncryptedTextField

# NEW IMPORTS (password history + validation)
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from datetime import timedelta


# ===================================================================
# USER MANAGER
# ===================================================================
class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        # Validate password strength
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


# ===================================================================
# PASSWORD HISTORY MODEL  (SCRUM-9 REQUIREMENT)
# ===================================================================
class PasswordHistory(models.Model):
    user = models.ForeignKey("User", on_delete=models.CASCADE)
    password_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


# ===================================================================
# USER MODEL
# ===================================================================
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

    # NEW: password expiry field (SCRUM-9)
    password_last_changed = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']


    # ==============================================
    # EMAIL VALIDATION
    # ==============================================
    def clean(self):
        super().clean()
        if self.email and not self.email.endswith('@capaciti.org.za'):
            raise ValidationError('Email must be a CAPACITI email address')


    # ==============================================
    # PASSWORD EXPIRY CHECK (90 days)
    # ==============================================
    def is_password_expired(self):
        return timezone.now() > self.password_last_changed + timedelta(days=90)


    # ==============================================
    # SAVE OVERRIDE - RECORD PASSWORD HISTORY
    # ==============================================
    def save(self, *args, **kwargs):

        # Run email validation
        self.clean()

        # If updating existing user:
        if self.pk:
            old_user = User.objects.get(pk=self.pk)

            # Password changed?
            if old_user.password != self.password:

                # Add old password hash to history
                PasswordHistory.objects.create(
                    user=self,
                    password_hash=old_user.password
                )

                # Keep only last 5 passwords
                history = PasswordHistory.objects.filter(user=self)[5:]
                PasswordHistory.objects.filter(id__in=[h.id for h in history]).delete()

                # Reset password expiry timer
                self.password_last_changed = timezone.now()

        super().save(*args, **kwargs)


    def __str__(self):
        return self.email



# ===================================================================
# USER PROFILE MODEL (unchanged)
# ===================================================================
class UserProfile(models.Model):
    """
    POPIA compliance:
    Encrypted PII fields for sensitive data:
    - SA ID numbers
    - Medical info
    - Emergency contacts
    - Doctor info
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    date_of_birth = models.DateField(null=True, blank=True)

    # Encrypted SA ID
    id_number = EncryptedCharField(max_length=255, null=True, blank=True)

    # Contact info
    contact_number = models.CharField(max_length=15, null=True, blank=True)
    address = models.TextField(null=True, blank=True)

    # Encrypted emergency contact info
    emergency_contact = EncryptedCharField(max_length=255, null=True, blank=True)
    emergency_phone = EncryptedCharField(max_length=255, null=True, blank=True)

    # Medical info (encrypted)
    diagnosis = EncryptedTextField(null=True, blank=True)
    medications = EncryptedTextField(null=True, blank=True)
    allergies = EncryptedTextField(null=True, blank=True)
    medical_notes = EncryptedTextField(null=True, blank=True)

    # Encrypted doctor info
    doctor_name = EncryptedCharField(max_length=255, null=True, blank=True)
    doctor_phone = EncryptedCharField(max_length=255, null=True, blank=True)

    # Non-sensitive fields
    accommodations = models.TextField(null=True, blank=True)
    assistive_technology = models.TextField(null=True, blank=True)
    learning_style = models.CharField(max_length=100, null=True, blank=True)
    support_needs = models.TextField(null=True, blank=True)
    communication_preferences = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"profile: {self.user.email}"