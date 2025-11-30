"""
SCRUM-10: Custom throttle classes for authentication endpoints
Stricter rate limiting for auth operations to prevent brute force attacks
"""
from rest_framework.throttling import AnonRateThrottle


class AuthRateThrottle(AnonRateThrottle):
    """
    Rate limiting for authentication endpoints (login, token refresh)
    Limit: 5 attempts per 15 minutes per IP
    """
    rate = '5/15min'


class RegisterRateThrottle(AnonRateThrottle):
    """
    Rate limiting for registration endpoint
    Limit: 3 attempts per hour per IP
    """
    rate = '3/hour'
