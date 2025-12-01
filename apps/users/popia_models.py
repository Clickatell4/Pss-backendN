"""
SCRUM-11: POPIA/GDPR Compliance Models

Models for managing user consent, privacy policy acceptance, and data deletion requests.
Required for POPIA Chapter 2 (Processing of Personal Information) compliance.
"""
from django.db import models
from django.utils import timezone
from .models import User
from auditlog.registry import auditlog


class PrivacyPolicyVersion(models.Model):
    """
    Tracks versions of privacy policy and terms of service.
    POPIA: Required to demonstrate consent versioning and policy changes.
    """
    version = models.CharField(max_length=20, unique=True)
    title = models.CharField(max_length=200)
    content = models.TextField(help_text="Full privacy policy text")
    effective_date = models.DateTimeField(help_text="When this version becomes effective")
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(
        default=False,
        help_text="Only one version should be active at a time"
    )

    class Meta:
        ordering = ['-effective_date']
        verbose_name = "Privacy Policy Version"
        verbose_name_plural = "Privacy Policy Versions"

    def __str__(self):
        return f"Privacy Policy v{self.version} ({'Active' if self.is_active else 'Inactive'})"

    def save(self, *args, **kwargs):
        # If this version is being set to active, deactivate all others
        if self.is_active:
            PrivacyPolicyVersion.objects.exclude(pk=self.pk).update(is_active=False)
        super().save(*args, **kwargs)


class UserConsent(models.Model):
    """
    Records user consent for data processing.
    POPIA Chapter 2, Section 11: Processing of personal information must be done with consent.
    """
    CONSENT_TYPES = [
        ('data_processing', 'General Data Processing'),
        ('medical_data', 'Medical Data Processing'),
        ('communications', 'Marketing Communications'),
        ('data_sharing', 'Data Sharing with Partners'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='consents')
    consent_type = models.CharField(max_length=50, choices=CONSENT_TYPES)
    privacy_policy_version = models.ForeignKey(
        PrivacyPolicyVersion,
        on_delete=models.PROTECT,
        help_text="Which privacy policy version user consented to"
    )
    granted = models.BooleanField(
        default=False,
        help_text="Whether consent was granted (True) or withdrawn (False)"
    )
    granted_at = models.DateTimeField(auto_now_add=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address when consent was granted (for audit trail)"
    )
    user_agent = models.TextField(
        blank=True,
        help_text="Browser user agent when consent was granted"
    )

    class Meta:
        ordering = ['-granted_at']
        verbose_name = "User Consent"
        verbose_name_plural = "User Consents"

    def __str__(self):
        status = "Granted" if self.granted else "Withdrawn"
        return f"{self.user.email} - {self.get_consent_type_display()} ({status})"

    def withdraw(self):
        """Withdraw consent (POPIA Right to Object - Section 11(3))"""
        self.granted = False
        self.withdrawn_at = timezone.now()
        self.save()


class DataDeletionRequest(models.Model):
    """
    Manages user requests for data deletion (Right to be Forgotten).
    POPIA Chapter 3, Section 16: Right to have personal information deleted.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='deletion_requests',
        help_text="User requesting data deletion"
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reason = models.TextField(
        blank=True,
        help_text="User's reason for requesting deletion (optional)"
    )

    # Admin review fields
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_deletion_requests',
        help_text="Admin who reviewed this request"
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    admin_notes = models.TextField(
        blank=True,
        help_text="Internal notes about the deletion decision"
    )

    # Completion tracking
    completed_at = models.DateTimeField(null=True, blank=True)
    deletion_proof = models.TextField(
        blank=True,
        help_text="Record of what data was deleted (for compliance proof)"
    )

    # POPIA: Retention period for deletion requests (keep record even after deletion)
    # Keep deletion request records for 2 years as proof of compliance
    retention_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Date until which this deletion record must be retained"
    )

    class Meta:
        ordering = ['-requested_at']
        verbose_name = "Data Deletion Request"
        verbose_name_plural = "Data Deletion Requests"

    def __str__(self):
        return f"Deletion Request: {self.user.email} ({self.get_status_display()})"

    def approve(self, admin_user, notes=''):
        """Approve deletion request"""
        self.status = 'approved'
        self.reviewed_by = admin_user
        self.reviewed_at = timezone.now()
        self.admin_notes = notes
        self.save()

    def reject(self, admin_user, reason):
        """Reject deletion request with reason"""
        self.status = 'rejected'
        self.reviewed_by = admin_user
        self.reviewed_at = timezone.now()
        self.admin_notes = reason
        self.save()

    def complete(self, deletion_summary):
        """Mark deletion as completed"""
        from datetime import timedelta
        self.status = 'completed'
        self.completed_at = timezone.now()
        self.deletion_proof = deletion_summary
        # Set retention period: 2 years from completion (POPIA requirement)
        self.retention_until = timezone.now() + timedelta(days=730)
        self.save()


class DataExportRequest(models.Model):
    """
    Tracks user requests for data export (Right to Access).
    POPIA Chapter 2, Section 18: Right to access personal information.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='export_requests')
    requested_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    completed_at = models.DateTimeField(null=True, blank=True)
    file_path = models.CharField(
        max_length=500,
        blank=True,
        help_text="Path to exported data file (if stored)"
    )
    download_count = models.IntegerField(
        default=0,
        help_text="Number of times the export was downloaded"
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the export file expires (24-48 hours typical)"
    )
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-requested_at']
        verbose_name = "Data Export Request"
        verbose_name_plural = "Data Export Requests"

    def __str__(self):
        return f"Export Request: {self.user.email} ({self.get_status_display()})"


# Register all compliance models for audit logging
auditlog.register(PrivacyPolicyVersion)
auditlog.register(UserConsent)
auditlog.register(DataDeletionRequest)
auditlog.register(DataExportRequest)
