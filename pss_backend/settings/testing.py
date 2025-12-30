"""
Django Testing/Staging Settings

Configuration for testing/staging environment on Render.
Uses Supabase PostgreSQL database and Supabase Storage.
"""
from .base import *
from decouple import config, Csv
import dj_database_url
import logging

_secrets_logger = logging.getLogger('django.security.secrets')

# =============================================================================
# Core Settings
# =============================================================================
DEBUG = config('DEBUG', cast=bool, default=False)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv(), default='localhost')

# =============================================================================
# Database Configuration (Supabase PostgreSQL)
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
    "Database: Supabase PostgreSQL (%s)",
    DATABASES['default']['HOST']
)

# =============================================================================
# Storage Configuration (Supabase Storage)
# =============================================================================
# Use Supabase Storage for media files
DEFAULT_FILE_STORAGE = 'pss_backend.storage_backends.SupabaseMediaStorage'

SUPABASE_URL = config('SUPABASE_URL')
SUPABASE_KEY = config('SUPABASE_KEY')
SUPABASE_STORAGE_BUCKET = config('SUPABASE_STORAGE_BUCKET', default='pss-testing-media')

MEDIA_URL = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_STORAGE_BUCKET}/"

_secrets_logger.info(
    "Media storage: Supabase Storage (bucket: %s)",
    SUPABASE_STORAGE_BUCKET
)

# =============================================================================
# Static Files
# =============================================================================
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

if (BASE_DIR / 'static').exists():
    STATICFILES_DIRS = [BASE_DIR / 'static']

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# =============================================================================
# CORS Configuration (Testing Frontend)
# =============================================================================
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    cast=Csv(),
    default='https://pss-frontend-testing.vercel.app'
)

CSRF_TRUSTED_ORIGINS = config(
    'CSRF_TRUSTED_ORIGINS',
    cast=Csv(),
    default='https://pss-frontend-testing.vercel.app'
)

_secrets_logger.info(
    "CORS allowed origins: %s",
    ', '.join(CORS_ALLOWED_ORIGINS)
)

# =============================================================================
# Security Settings (Testing - Production-like)
# =============================================================================
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# =============================================================================
# CAPTCHA Configuration (Testing)
# =============================================================================
# Enable CAPTCHA but with slightly relaxed threshold for testing
CAPTCHA_ENABLED = config('CAPTCHA_ENABLED', cast=bool, default=True)
CAPTCHA_TRIGGER_THRESHOLD = config('CAPTCHA_TRIGGER_THRESHOLD', cast=int, default=5)

_secrets_logger.info(
    "CAPTCHA enabled: %s, trigger threshold: %d attempts",
    CAPTCHA_ENABLED, CAPTCHA_TRIGGER_THRESHOLD
)

# =============================================================================
# Email Configuration (Testing)
# =============================================================================
# Use SMTP backend for testing (sends real emails)
EMAIL_BACKEND = config(
    'EMAIL_BACKEND',
    default='django.core.mail.backends.smtp.EmailBackend'
)

FRONTEND_URL = config('FRONTEND_URL', default='https://pss-frontend-testing.vercel.app')

_secrets_logger.info(
    "Email backend: SMTP (%s:%s)",
    EMAIL_HOST, EMAIL_PORT
)
_secrets_logger.info(
    "Frontend URL: %s",
    FRONTEND_URL
)

# =============================================================================
# Logging (Testing Environment)
# =============================================================================
# Update logging formatter to indicate testing environment
LOGGING['formatters']['verbose'] = {
    'format': '[TESTING] {levelname} {asctime} {module} {message}',
    'style': '{',
}

_secrets_logger.info("=" * 70)
_secrets_logger.info("ENVIRONMENT: Testing/Staging (Render)")
_secrets_logger.info("Database: Supabase PostgreSQL")
_secrets_logger.info("Storage: Supabase Storage")
_secrets_logger.info("CAPTCHA: Enabled (threshold: %d)", CAPTCHA_TRIGGER_THRESHOLD)
_secrets_logger.info("=" * 70)
