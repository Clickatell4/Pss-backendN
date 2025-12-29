"""
SCRUM-30: Django Admin Configuration for Session Management
Rich admin interface for viewing and managing user sessions and password reset tokens
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from apps.authentication.models import UserSession, PasswordResetToken


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """
    Django admin interface for UserSession model.

    Features:
    - Device and status badges with icons
    - Filtering by device type, suspicious flag, dates
    - Search by user email, IP, browser, session key
    - Admin actions for bulk termination
    - All fields readonly (no editing)
    """

    list_display = [
        'id',
        'user_email',
        'device_badge',
        'browser',
        'ip_address',
        'location_display',
        'status_badge',
        'suspicious_badge',
        'last_activity',
    ]

    list_filter = [
        'device_type',
        'is_suspicious',
        'created_at',
        'last_activity',
    ]

    search_fields = [
        'user__email',
        'ip_address',
        'browser',
        'os',
        'session_key',
    ]

    readonly_fields = [
        'user',
        'outstanding_token',
        'session_key',
        'device_type',
        'browser',
        'os',
        'user_agent',
        'ip_address',
        'country',
        'city',
        'created_at',
        'last_activity',
        'expires_at',
        'is_suspicious',
        'terminated_at',
        'status_badge',
        'device_badge',
    ]

    fieldsets = (
        ('User Information', {
            'fields': ('user', 'session_key')
        }),
        ('Device Metadata', {
            'fields': ('device_type', 'device_badge', 'browser', 'os', 'user_agent')
        }),
        ('Location', {
            'fields': ('ip_address', 'country', 'city')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'last_activity', 'expires_at', 'terminated_at')
        }),
        ('Security', {
            'fields': ('is_suspicious', 'status_badge', 'outstanding_token')
        }),
    )

    ordering = ['-last_activity']

    actions = ['terminate_sessions', 'mark_as_suspicious']

    def user_email(self, obj):
        """Display user email."""
        return obj.user.email if obj.user else 'N/A'
    user_email.short_description = 'User'
    user_email.admin_order_field = 'user__email'

    def device_badge(self, obj):
        """Display device type with icon."""
        icons = {
            'mobile': '📱',
            'tablet': '📱',
            'pc': '💻',
            'bot': '🤖',
            'unknown': '❓',
        }
        icon = icons.get(obj.device_type, '❓')
        return format_html(
            '<span style="font-size: 16px;">{} {}</span>',
            icon,
            obj.get_device_type_display()
        )
    device_badge.short_description = 'Device'

    def location_display(self, obj):
        """Display location (country, city) or IP if no location."""
        if obj.country or obj.city:
            parts = [p for p in [obj.city, obj.country] if p]
            return ', '.join(parts)
        return obj.ip_address or 'Unknown'
    location_display.short_description = 'Location'

    def status_badge(self, obj):
        """Display status with color badge."""
        if obj.terminated_at:
            color = '#dc3545'  # Red
            status = 'Terminated'
        elif obj.is_expired:
            color = '#6c757d'  # Gray
            status = 'Expired'
        elif obj.is_active:
            color = '#28a745'  # Green
            status = 'Active'
        else:
            color = '#ffc107'  # Yellow
            status = 'Unknown'

        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color,
            status
        )
    status_badge.short_description = 'Status'

    def suspicious_badge(self, obj):
        """Display suspicious flag with icon."""
        if obj.is_suspicious:
            return format_html(
                '<span style="color: #dc3545; font-size: 16px;" title="Suspicious login">⚠️</span>'
            )
        return format_html(
            '<span style="color: #28a745; font-size: 16px;" title="Normal login">✓</span>'
        )
    suspicious_badge.short_description = 'Suspicious'

    def terminate_sessions(self, request, queryset):
        """Admin action to terminate selected sessions."""
        count = 0
        for session in queryset:
            if not session.terminated_at:
                session.terminate()
                count += 1

        self.message_user(
            request,
            f'Terminated {count} session(s).'
        )
    terminate_sessions.short_description = 'Terminate selected sessions'

    def mark_as_suspicious(self, request, queryset):
        """Admin action to mark selected sessions as suspicious."""
        count = queryset.update(is_suspicious=True)
        self.message_user(
            request,
            f'Marked {count} session(s) as suspicious.'
        )
    mark_as_suspicious.short_description = 'Mark as suspicious'

    def has_add_permission(self, request):
        """Disable adding sessions via admin (created automatically)."""
        return False

    def has_change_permission(self, request, obj=None):
        """Disable editing sessions via admin (view-only)."""
        return False


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    """
    Django admin interface for PasswordResetToken model.

    Features:
    - Status badges with colors
    - Filtering by status, dates
    - Search by user email, IP
    - All fields readonly
    """

    list_display = [
        'id',
        'user_email',
        'status_badge',
        'created_at',
        'expires_at',
        'ip_address',
        'used_at',
    ]

    list_filter = [
        'used',
        'created_at',
        'expires_at',
    ]

    search_fields = [
        'user__email',
        'ip_address',
    ]

    readonly_fields = [
        'user',
        'token_hash',
        'created_at',
        'expires_at',
        'used',
        'used_at',
        'ip_address',
        'user_agent',
        'status_badge',
    ]

    fieldsets = (
        ('User Information', {
            'fields': ('user', 'token_hash')
        }),
        ('Status', {
            'fields': ('status_badge', 'used', 'used_at')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'expires_at')
        }),
        ('Request Metadata', {
            'fields': ('ip_address', 'user_agent')
        }),
    )

    ordering = ['-created_at']

    def user_email(self, obj):
        """Display user email."""
        return obj.user.email if obj.user else 'N/A'
    user_email.short_description = 'User'
    user_email.admin_order_field = 'user__email'

    def status_badge(self, obj):
        """Display status with color badge."""
        if obj.used:
            color = '#6c757d'  # Gray
            status = 'Used'
        elif obj.expires_at < timezone.now():
            color = '#dc3545'  # Red
            status = 'Expired'
        else:
            color = '#28a745'  # Green
            status = 'Valid'

        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color,
            status
        )
    status_badge.short_description = 'Status'

    def has_add_permission(self, request):
        """Disable adding tokens via admin (created automatically)."""
        return False

    def has_change_permission(self, request, obj=None):
        """Disable editing tokens via admin (view-only)."""
        return False
