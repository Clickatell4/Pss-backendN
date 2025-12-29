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
        expiry_date = self.password_last_changed + timedelta(days=90)
        return timezone.now() > expiry_date

    def save(self, *args, **kwargs):
        self.clean()

        if self.pk:
            try:
                old_user = User.objects.get(pk=self.pk)
                if old_user.password != self.password:
                    from .popia_models import PasswordHistory

                    history = PasswordHistory.objects.filter(user=self).order_by('-created_at')[:5]
                    for hist in history:
                        if self.check_password(hist.password_hash):
                            raise ValidationError(
                                'Cannot reuse your last 5 passwords. Please choose a different password.'
                            )

                    PasswordHistory.objects.create(
                        user=self,
                        password_hash=old_user.password
                    )

                    old_passwords = PasswordHistory.objects.filter(user=self).order_by('-created_at')[5:]
                    for old_pass in old_passwords:
                        old_pass.delete()

                    self.password_last_changed = timezone.now()
            except User.DoesNotExist:
                pass

        super().save(*args, **kwargs)

    def __str__(self):
        return self.email


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')

    id_number = EncryptedCharField(max_length=255, null=True, blank=True)
    contact_number = models.CharField(max_length=15, null=True, blank=True)
    address = models.TextField(null=True, blank=True)

    emergency_contact = EncryptedCharField(max_length=255, null=True, blank=True)
    emergency_phone = EncryptedCharField(max_length=255, null=True, blank=True)

    diagnosis = EncryptedTextField(null=True, blank=True)
    medications = EncryptedTextField(null=True, blank=True)
    allergies = EncryptedTextField(null=True, blank=True)
    medical_notes = EncryptedTextField(null=True, blank=True)

    doctor_name = EncryptedCharField(max_length=255, null=True, blank=True)
    doctor_phone = EncryptedCharField(max_length=255, null=True, blank=True)

    accommodations = models.TextField(null=True, blank=True)
    assistive_technology = models.TextField(null=True, blank=True)
    learning_style = models.CharField(max_length=100, null=True, blank=True)
    support_needs = models.TextField(null=True, blank=True)
    communication_preferences = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"profile: {self.user.email}"


class AccountDeletionSchedule(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='deletion_schedule')
    scheduled_deletion_date = models.DateTimeField()
    first_warning_sent = models.DateTimeField(null=True, blank=True)
    second_warning_sent = models.DateTimeField(null=True, blank=True)
    exempted = models.BooleanField(default=False)
    exemption_reason = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['scheduled_deletion_date']

    def __str__(self):
        return f"{self.user.email} deletion schedule"

    @property
    def days_until_deletion(self):
        if self.exempted:
            return None
        delta = self.scheduled_deletion_date - timezone.now()
        return max(0, delta.days)

    @property
    def is_overdue(self):
        if self.exempted:
            return False
        return timezone.now() > self.scheduled_deletion_date


auditlog.register(User, exclude_fields=['password', 'last_login'])
auditlog.register(UserProfile)
auditlog.register(AccountDeletionSchedule)

from .popia_models import (  # noqa: E402
    PrivacyPolicyVersion,
    UserConsent,
    DataDeletionRequest,
    DataExportRequest,
)
