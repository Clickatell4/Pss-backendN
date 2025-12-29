from django.contrib import admin
from django.utils.html import format_html
from .models import User, UserProfile, AccountDeletionSchedule
from .popia_models import (
    PrivacyPolicyVersion,
    UserConsent,
    DataDeletionRequest,
    DataExportRequest
)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'first_name', 'last_name', 'role', 'totp_badge', 'has_completed_intake', 'date_joined', 'is_staff']
    list_filter = ['role', 'totp_enabled', 'has_completed_intake', 'date_joined', 'is_staff']
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ('email',)
    actions = ['disable_2fa_recovery']

    def totp_badge(self, obj):
        """
        Display 2FA status with icon.

        SCRUM-14: Shows whether user has 2FA enabled
        - 🔒 Green: 2FA enabled
        - 🔓 Gray: 2FA disabled
        """
        if obj.totp_enabled:
            return format_html(
                '<span style="color: #28a745; font-size: 16px;" title="2FA Enabled">🔒</span>'
            )
        else:
            return format_html(
                '<span style="color: #6c757d; font-size: 16px;" title="2FA Disabled">🔓</span>'
            )
    totp_badge.short_description = '2FA'

    def disable_2fa_recovery(self, request, queryset):
        """
        Admin action to disable 2FA for selected users (emergency recovery only).

        SCRUM-14: Allows admins to disable 2FA for users who lost access to
        their authenticator app. This is an emergency recovery mechanism.

        Security:
        - Requires admin authentication
        - Deletes all backup codes
        - Clears TOTP secret
        - Logged to audit trail
        """
        count = 0
        for user in queryset:
            if user.totp_enabled:
                # Disable 2FA
                user.totp_secret = None
                user.totp_enabled = False
                user.totp_enabled_at = None
                user.totp_last_used = None
                user.save(update_fields=['totp_secret', 'totp_enabled', 'totp_enabled_at', 'totp_last_used'])

                # Delete all backup codes
                from apps.authentication.models import TwoFactorBackupCode
                TwoFactorBackupCode.objects.filter(user=user).delete()

                count += 1

                # Log admin action
                import logging
                logger = logging.getLogger('django.security.auth')
                logger.warning(
                    f"ADMIN 2FA RECOVERY | Admin: {request.user.email} | "
                    f"Target: {user.email} | Reason: Admin override"
                )

        self.message_user(
            request,
            f'Disabled 2FA for {count} user(s). Users will need to re-enable 2FA on next login (if admin/superuser).'
        )
    disable_2fa_recovery.short_description = 'Disable 2FA (Emergency Recovery)'

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'diagnosis', 'created_at']
    search_fields = ['user__email', 'diagnosis']


# =============================================================================
# SCRUM-11: POPIA Compliance Admin Models
# =============================================================================

@admin.register(PrivacyPolicyVersion)
class PrivacyPolicyVersionAdmin(admin.ModelAdmin):
    list_display = ['version', 'title', 'effective_date', 'is_active', 'created_at']
    list_filter = ['is_active', 'effective_date']
    search_fields = ['version', 'title']
    readonly_fields = ['created_at']
    ordering = ['-effective_date']

    def get_readonly_fields(self, request, obj=None):
        # Make version read-only after creation
        if obj:
            return self.readonly_fields + ['version']
        return self.readonly_fields


@admin.register(UserConsent)
class UserConsentAdmin(admin.ModelAdmin):
    list_display = ['user', 'consent_type', 'granted_status', 'privacy_policy_version', 'granted_at']
    list_filter = ['consent_type', 'granted', 'granted_at']
    search_fields = ['user__email', 'consent_type']
    readonly_fields = ['granted_at', 'withdrawn_at', 'ip_address', 'user_agent']
    ordering = ['-granted_at']

    def granted_status(self, obj):
        if obj.granted:
            return format_html('<span style="color: green;">✓ Granted</span>')
        else:
            return format_html('<span style="color: red;">✗ Withdrawn</span>')
    granted_status.short_description = 'Status'


@admin.register(DataDeletionRequest)
class DataDeletionRequestAdmin(admin.ModelAdmin):
    list_display = ['user', 'status_badge', 'requested_at', 'reviewed_by', 'reviewed_at']
    list_filter = ['status', 'requested_at', 'reviewed_at']
    search_fields = ['user__email', 'reason', 'admin_notes']
    readonly_fields = ['requested_at', 'reviewed_at', 'completed_at', 'retention_until']
    ordering = ['-requested_at']

    fieldsets = (
        ('Request Information', {
            'fields': ('user', 'status', 'reason', 'requested_at')
        }),
        ('Admin Review', {
            'fields': ('reviewed_by', 'reviewed_at', 'admin_notes')
        }),
        ('Completion Details', {
            'fields': ('completed_at', 'deletion_proof', 'retention_until')
        }),
    )

    def status_badge(self, obj):
        colors = {
            'pending': 'orange',
            'approved': 'green',
            'rejected': 'red',
            'completed': 'blue',
            'cancelled': 'gray',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(DataExportRequest)
class DataExportRequestAdmin(admin.ModelAdmin):
    list_display = ['user', 'status_badge', 'requested_at', 'completed_at', 'download_count']
    list_filter = ['status', 'requested_at', 'completed_at']
    search_fields = ['user__email']
    readonly_fields = ['requested_at', 'completed_at', 'download_count', 'expires_at']
    ordering = ['-requested_at']

    def status_badge(self, obj):
        colors = {
            'pending': 'orange',
            'processing': 'blue',
            'completed': 'green',
            'failed': 'red',
        }
        color = colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(AccountDeletionSchedule)
class AccountDeletionScheduleAdmin(admin.ModelAdmin):
    list_display = ['user', 'scheduled_deletion_date', 'days_remaining', 'exempted', 'first_warning_sent', 'second_warning_sent']
    list_filter = ['exempted', 'scheduled_deletion_date', 'first_warning_sent', 'second_warning_sent']
    search_fields = ['user__email', 'exemption_reason']
    readonly_fields = ['created_at', 'updated_at', 'days_remaining', 'is_overdue']
    ordering = ['scheduled_deletion_date']

    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Deletion Schedule', {
            'fields': ('scheduled_deletion_date', 'days_remaining', 'is_overdue')
        }),
        ('Warnings', {
            'fields': ('first_warning_sent', 'second_warning_sent')
        }),
        ('Exemption', {
            'fields': ('exempted', 'exemption_reason')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['exempt_from_deletion', 'remove_exemption']

    def days_remaining(self, obj):
        days = obj.days_until_deletion
        if obj.exempted:
            return format_html('<span style="color: green; font-weight: bold;">EXEMPTED</span>')
        elif days is None:
            return '-'
        elif days == 0:
            return format_html('<span style="color: red; font-weight: bold;">TODAY</span>')
        elif days < 0:
            return format_html('<span style="color: red; font-weight: bold;">OVERDUE by {} days</span>', abs(days))
        elif days <= 7:
            return format_html('<span style="color: orange; font-weight: bold;">{} days</span>', days)
        else:
            return f'{days} days'
    days_remaining.short_description = 'Days Until Deletion'

    def exempt_from_deletion(self, request, queryset):
        count = queryset.update(exempted=True, exemption_reason='Manually exempted by admin')
        self.message_user(request, f'{count} account(s) exempted from deletion.')
    exempt_from_deletion.short_description = 'Exempt selected accounts from deletion'

    def remove_exemption(self, request, queryset):
        count = queryset.update(exempted=False, exemption_reason='')
        self.message_user(request, f'{count} account(s) exemption removed.')
    remove_exemption.short_description = 'Remove exemption from selected accounts'
