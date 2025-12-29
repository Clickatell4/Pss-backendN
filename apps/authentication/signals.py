"""
SCRUM-8: Authentication event logging
SCRUM-30: Session management signal handlers
Logs all authentication events for security monitoring and compliance
Creates user sessions with device metadata on token creation
"""
import logging
import hashlib
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.utils import timezone
from user_agents import parse

try:
    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
except ImportError:
    OutstandingToken = None

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


# SCRUM-30: Session Management Signal Handlers

def parse_user_agent(user_agent_string):
    """
    Parse user agent string to extract device type, browser, and OS.

    Args:
        user_agent_string: Raw user agent string from request

    Returns:
        tuple: (device_type, browser, os)
    """
    if not user_agent_string:
        return ('unknown', '', '')

    try:
        ua = parse(user_agent_string)

        # Determine device type
        if ua.is_mobile:
            device_type = 'mobile'
        elif ua.is_tablet:
            device_type = 'tablet'
        elif ua.is_pc:
            device_type = 'pc'
        elif ua.is_bot:
            device_type = 'bot'
        else:
            device_type = 'unknown'

        # Extract browser and OS
        browser = f"{ua.browser.family} {ua.browser.version_string}".strip()
        os = f"{ua.os.family} {ua.os.version_string}".strip()

        return (device_type, browser, os)
    except Exception:
        return ('unknown', '', '')


def detect_suspicious_login(user, ip_address, user_agent):
    """
    Detect if a login is suspicious based on previous session history.

    A login is considered suspicious if it's from a new device or IP address
    that hasn't been seen before for this user.

    Args:
        user: User instance
        ip_address: IP address of the login attempt
        user_agent: User agent string

    Returns:
        bool: True if suspicious, False otherwise
    """
    if not user:
        return False

    # Avoid circular import
    from apps.authentication.models import UserSession

    try:
        # Check if user has any previous sessions with this IP or device fingerprint
        device_type, browser, os = parse_user_agent(user_agent)

        previous_sessions = UserSession.objects.filter(
            user=user
        ).values_list('ip_address', 'device_type', 'browser', 'os')

        # If no previous sessions, not suspicious (first login)
        if not previous_sessions.exists():
            return False

        # Check if we've seen this IP or device combination before
        for prev_ip, prev_device, prev_browser, prev_os in previous_sessions:
            # Match by IP OR by device fingerprint (device + browser + os)
            if prev_ip == ip_address:
                return False  # Same IP seen before
            if (prev_device == device_type and
                prev_browser == browser and
                prev_os == os):
                return False  # Same device seen before

        # New device and IP - suspicious
        return True
    except Exception:
        # If detection fails, default to not suspicious
        return False


@receiver(post_save, sender=OutstandingToken if OutstandingToken else type(None))
def create_user_session(sender, instance, created, **kwargs):
    """
    SCRUM-30: Create a UserSession when an OutstandingToken is created.

    This signal creates session metadata when a user logs in and a refresh token
    is generated. It extracts device info, IP address, and detects suspicious logins.

    Args:
        sender: OutstandingToken model class
        instance: OutstandingToken instance that was saved
        created: Boolean indicating if this is a new instance
        **kwargs: Additional signal arguments
    """
    if not created or not instance:
        return

    # Avoid circular import
    from apps.authentication.models import UserSession

    # Get request context if attached (set by LoginView)
    request = getattr(instance, '_request_context', None)

    # Extract metadata from request
    ip_address = get_client_ip(request) if request else None
    if ip_address == 'Unknown':
        ip_address = None

    user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''

    # Parse user agent
    device_type, browser, os = parse_user_agent(user_agent)

    # Detect suspicious login
    is_suspicious = detect_suspicious_login(instance.user, ip_address, user_agent)

    # Generate session key (SHA256 hash of token jti)
    session_key = hashlib.sha256(str(instance.jti).encode()).hexdigest()

    try:
        # Create UserSession
        UserSession.create_session(
            user=instance.user,
            outstanding_token=instance,
            session_key=session_key,
            device_type=device_type,
            browser=browser,
            os=os,
            user_agent=user_agent,
            ip_address=ip_address,
            is_suspicious=is_suspicious
        )

        # Log session creation
        auth_logger.info(
            f"SESSION CREATED | User: {instance.user.email} | Device: {device_type} | "
            f"IP: {ip_address} | Suspicious: {is_suspicious} | Time: {timezone.now().isoformat()}"
        )
    except Exception as e:
        # Log error but don't break the login flow
        auth_logger.error(
            f"SESSION CREATION FAILED | User: {instance.user.email} | "
            f"Error: {str(e)} | Time: {timezone.now().isoformat()}"
        )
