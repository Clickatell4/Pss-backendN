from django.contrib import admin
from django.utils.html import format_html
from .models import User, UserProfile
from .popia_models import (
    PrivacyPolicyVersion,
    UserConsent,
    DataDeletionRequest,
    DataExportRequest
)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'first_name', 'last_name', 'role', 'has_completed_intake', 'date_joined', 'is_staff']
    list_filter = ['role', 'has_completed_intake', 'date_joined', 'is_staff']
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ('email',)

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
