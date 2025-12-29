"""
SCRUM-30: Session Activity Tracking Middleware
Updates last_activity timestamp for authenticated user sessions
"""
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin


class SessionActivityMiddleware(MiddlewareMixin):
    """
    Middleware to track user session activity.

    Updates the last_activity timestamp for the user's active session
    on every authenticated request. This helps identify inactive sessions
    and provides user visibility into when they last used each device.

    Implementation Notes:
    - Runs on every request after authentication
    - Silently fails if session tracking fails (doesn't break requests)
    - Only updates if user is authenticated
    - Uses approximate matching (most recent session by user)
    """

    def process_request(self, request):
        """
        Update last_activity for authenticated user's session.

        Args:
            request: Django request object
        """
        # Only track activity for authenticated users
        if not request.user or not request.user.is_authenticated:
            return None

        try:
            # Lazy import to avoid circular dependency
            from apps.authentication.models import UserSession

            # Find the user's most recent active session
            # Note: We can't perfectly match the current session from the access token,
            # so we approximate by updating the most recently active session
            session = UserSession.objects.filter(
                user=request.user,
                terminated_at__isnull=True,
                expires_at__gt=timezone.now()
            ).order_by('-last_activity').first()

            if session:
                # Only update if last activity was more than 5 minutes ago
                # This prevents excessive database writes on every request
                time_since_activity = timezone.now() - session.last_activity
                if time_since_activity.total_seconds() > 300:  # 5 minutes
                    session.update_activity()

        except Exception:
            # Silently fail - don't break the request if session tracking fails
            pass

        return None
