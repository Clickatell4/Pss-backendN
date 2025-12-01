"""
SCRUM-8: Authentication event logging
Logs all authentication events for security monitoring and compliance
"""
import logging
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.utils import timezone

# Create logger for authentication events
auth_logger = logging.getLogger('django.security.auth')


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """
    Log successful user login events.
    Records: timestamp, user email, IP address, user agent
    """
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')

    auth_logger.info(
        f"LOGIN SUCCESS | User: {user.email} | IP: {ip_address} | "
        f"User-Agent: {user_agent[:100]} | Time: {timezone.now().isoformat()}"
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """
    Log user logout events.
    Records: timestamp, user email (if available), IP address
    """
    ip_address = get_client_ip(request)
    user_email = user.email if user else 'Unknown'

    auth_logger.info(
        f"LOGOUT | User: {user_email} | IP: {ip_address} | "
        f"Time: {timezone.now().isoformat()}"
    )


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """
    Log failed login attempts.
    Records: timestamp, attempted email, IP address
    IMPORTANT: For security monitoring and detecting brute force attacks
    """
    ip_address = get_client_ip(request)
    attempted_email = credentials.get('username', 'Unknown')
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown') if request else 'Unknown'

    auth_logger.warning(
        f"LOGIN FAILED | Attempted Email: {attempted_email} | IP: {ip_address} | "
        f"User-Agent: {user_agent[:100]} | Time: {timezone.now().isoformat()}"
    )


def get_client_ip(request):
    """
    Extract client IP address from request.
    Handles proxy scenarios (X-Forwarded-For header)
    """
    if not request:
        return 'Unknown'

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Get first IP in chain (original client)
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', 'Unknown')

    return ip
