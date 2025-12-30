"""
Django Production Settings

Configuration for production environment on internal server.
Uses PostgreSQL database and local file storage.
"""
from .base import *
from decouple import config, Csv
import dj_database_url
import logging

_secrets_logger = logging.getLogger('django.security.secrets')

# =============================================================================
# Core Settings
# =============================================================================
DEBUG = False
ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv())

# =============================================================================
# Database Configuration (Production PostgreSQL)
# =============================================================================
DATABASE_URL = config('DATABASE_URL')
DATABASES = {
    'default': dj_database_url.parse(
        DATABASE_URL,
        conn_max_age=600,
        ssl_require=True
    )
}

_secrets_logger.info(
    "Database: Production PostgreSQL (%s)",
    DATABASES['default']['HOST']
)

# =============================================================================
# Static and Media Files
# =============================================================================
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

if (BASE_DIR / 'static').exists():
    STATICFILES_DIRS = [BASE_DIR / 'static']

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# =============================================================================
# CORS Configuration (Production Frontend)
# =============================================================================
CORS_ALLOWED_ORIGINS = [
    "https://pss-frontend-ebon.vercel.app",
]

CSRF_TRUSTED_ORIGINS = config(
    'CSRF_TRUSTED_ORIGINS',
    cast=Csv(),
    default='https://pss-frontend-ebon.vercel.app'
)

_secrets_logger.info(
    "CORS allowed origins: %s",
    ', '.join(CORS_ALLOWED_ORIGINS)
)

# =============================================================================
# Security Settings (Production - Strict)
# =============================================================================
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# =============================================================================
# CAPTCHA Configuration (Production - Strict)
# =============================================================================
CAPTCHA_ENABLED = True
CAPTCHA_TRIGGER_THRESHOLD = config('CAPTCHA_TRIGGER_THRESHOLD', cast=int, default=3)

_secrets_logger.info(
    "CAPTCHA enabled: %s, trigger threshold: %d attempts",
    CAPTCHA_ENABLED, CAPTCHA_TRIGGER_THRESHOLD
)

# =============================================================================
# Email Configuration (Production)
# =============================================================================
# Use SMTP backend for production (sends real emails)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
FRONTEND_URL = config('FRONTEND_URL', default='https://pss-frontend-ebon.vercel.app')

_secrets_logger.info(
    "Email backend: SMTP (%s:%s)",
    EMAIL_HOST, EMAIL_PORT
)
_secrets_logger.info(
    "Frontend URL: %s",
    FRONTEND_URL
)

# =============================================================================
# Logging (Production Environment)
# =============================================================================
# Update logging formatter to indicate production environment
LOGGING['formatters']['verbose'] = {
    'format': '[PRODUCTION] {levelname} {asctime} {module} {message}',
    'style': '{',
}

_secrets_logger.info("=" * 70)
_secrets_logger.info("ENVIRONMENT: Production (Internal Server)")
_secrets_logger.info("Database: Production PostgreSQL")
_secrets_logger.info("Storage: Local file storage")
_secrets_logger.info("CAPTCHA: Enabled (threshold: %d)", CAPTCHA_TRIGGER_THRESHOLD)
_secrets_logger.info("=" * 70)
