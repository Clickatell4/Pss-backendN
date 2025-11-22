from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from encrypted_model_fields.fields import EncryptedCharField, EncryptedTextField

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
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    date_of_birth = models.DateField(null=True, blank=True)

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

    def __str__(self):
        return f"profile: {self.user.email}"
