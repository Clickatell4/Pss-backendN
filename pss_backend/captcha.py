"""
SCRUM-120: CAPTCHA Verification Utility

Provides CAPTCHA verification for brute force protection.
Integrates with rate limiting (SCRUM-10) to add human verification layer.

Supported providers:
- Google reCAPTCHA v3 (recommended - invisible, risk-based scoring)
- hCaptcha (privacy-focused alternative)
- Cloudflare Turnstile (privacy-focused, newer)
"""
import requests
import logging
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger('django.security.auth')


class CaptchaVerificationError(Exception):
    """Raised when CAPTCHA verification fails."""
    pass


def verify_recaptcha(token, action='login', remote_ip=None):
    """
    Verify Google reCAPTCHA v3 token.

    Args:
        token (str): reCAPTCHA token from frontend
        action (str): Expected action name (prevents token reuse)
        remote_ip (str): Optional user IP for additional verification

    Returns:
        tuple: (success: bool, score: float, error_message: str)

    Raises:
        CaptchaVerificationError: If verification request fails
    """
    if not token:
        logger.warning(f'CAPTCHA verification attempted without token (action: {action})')
        return False, 0.0, 'CAPTCHA token is required'

    try:
        data = {
            'secret': settings.RECAPTCHA_PRIVATE_KEY,
            'response': token,
        }

        if remote_ip:
            data['remoteip'] = remote_ip

        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data=data,
            timeout=5  # 5 second timeout
        )
        response.raise_for_status()
        result = response.json()

    except requests.RequestException as e:
        logger.error(f'CAPTCHA verification request failed: {str(e)}')
        raise CaptchaVerificationError('CAPTCHA service unavailable')

    except Exception as e:
        logger.error(f'CAPTCHA verification error: {str(e)}')
        raise CaptchaVerificationError('CAPTCHA verification failed')

    # Check if verification succeeded
    if not result.get('success', False):
        error_codes = result.get('error-codes', [])
        logger.warning(
            f'CAPTCHA verification failed (action: {action}, errors: {error_codes})'
        )
        return False, 0.0, 'CAPTCHA verification failed'

    # For reCAPTCHA v3, check score threshold
    score = result.get('score', 0.0)
    if score < settings.RECAPTCHA_REQUIRED_SCORE:
        logger.warning(
            f'CAPTCHA score too low (action: {action}, score: {score}, '
            f'threshold: {settings.RECAPTCHA_REQUIRED_SCORE})'
        )
        return False, score, f'CAPTCHA score too low: {score}'

    # Check action matches (prevents token reuse across different forms)
    result_action = result.get('action', '')
    if result_action != action:
        logger.warning(
            f'CAPTCHA action mismatch (expected: {action}, got: {result_action})'
        )
        return False, score, 'CAPTCHA action mismatch'

    logger.info(
        f'CAPTCHA verification successful (action: {action}, score: {score})'
    )
    return True, score, ''


def verify_captcha(token, action='login', remote_ip=None):
    """
    Verify CAPTCHA token using configured provider.

    This is the main entry point for CAPTCHA verification.
    Routes to the appropriate provider based on settings.

    Args:
        token (str): CAPTCHA token from frontend
        action (str): Expected action name
        remote_ip (str): Optional user IP

    Returns:
        tuple: (success: bool, score: float, error_message: str)
    """
    if not settings.CAPTCHA_ENABLED:
        logger.debug('CAPTCHA disabled, skipping verification')
        return True, 1.0, ''

    # Check if IP is whitelisted
    if remote_ip and remote_ip in settings.CAPTCHA_BYPASS_IPS:
        logger.info(f'CAPTCHA bypassed for whitelisted IP: {remote_ip}')
        return True, 1.0, ''

    provider = settings.CAPTCHA_PROVIDER.lower()

    if provider == 'recaptcha':
        return verify_recaptcha(token, action, remote_ip)
    elif provider == 'hcaptcha':
        # TODO: Implement hCaptcha verification
        logger.warning('hCaptcha not implemented, falling back to reCAPTCHA')
        return verify_recaptcha(token, action, remote_ip)
    elif provider == 'turnstile':
        # TODO: Implement Cloudflare Turnstile verification
        logger.warning('Turnstile not implemented, falling back to reCAPTCHA')
        return verify_recaptcha(token, action, remote_ip)
    else:
        logger.error(f'Unknown CAPTCHA provider: {provider}')
        return False, 0.0, 'Invalid CAPTCHA provider configuration'


def track_failed_login_attempt(identifier):
    """
    Track failed login attempts for a given identifier (IP + email).

    Args:
        identifier (str): Unique identifier (e.g., "192.168.1.1:user@example.com")

    Returns:
        int: Number of failed attempts
    """
    cache_key = f'failed_login:{identifier}'
    attempts = cache.get(cache_key, 0)
    attempts += 1
    cache.set(cache_key, attempts, timeout=settings.CAPTCHA_FAILED_LOGIN_TIMEOUT)

    logger.debug(f'Failed login attempt tracked: {identifier} ({attempts} attempts)')
    return attempts


def get_failed_login_attempts(identifier):
    """
    Get number of failed login attempts for a given identifier.

    Args:
        identifier (str): Unique identifier (e.g., "192.168.1.1:user@example.com")

    Returns:
        int: Number of failed attempts
    """
    cache_key = f'failed_login:{identifier}'
    return cache.get(cache_key, 0)


def reset_failed_login_attempts(identifier):
    """
    Reset failed login attempts after successful login.

    Args:
        identifier (str): Unique identifier (e.g., "192.168.1.1:user@example.com")
    """
    cache_key = f'failed_login:{identifier}'
    cache.delete(cache_key)
    logger.debug(f'Failed login attempts reset: {identifier}')


def is_captcha_required(identifier):
    """
    Check if CAPTCHA is required based on failed login attempts.

    Args:
        identifier (str): Unique identifier (e.g., "192.168.1.1:user@example.com")

    Returns:
        bool: True if CAPTCHA is required
    """
    if not settings.CAPTCHA_ENABLED:
        return False

    attempts = get_failed_login_attempts(identifier)
    required = attempts >= settings.CAPTCHA_TRIGGER_THRESHOLD

    if required:
        logger.info(
            f'CAPTCHA required for {identifier} '
            f'({attempts}/{settings.CAPTCHA_TRIGGER_THRESHOLD} attempts)'
        )

    return required


def get_client_ip(request):
    """
    Extract client IP address from request, accounting for proxies.

    Args:
        request: Django request object

    Returns:
        str: Client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Get first IP in the chain (original client)
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '')

    return ip


def create_login_identifier(ip, email):
    """
    Create unique identifier for tracking failed login attempts.

    Combines IP and email to track attempts per user per location.
    This prevents a single IP from locking out all users, and vice versa.

    Args:
        ip (str): Client IP address
        email (str): User email address

    Returns:
        str: Unique identifier
    """
    return f'{ip}:{email.lower()}'
