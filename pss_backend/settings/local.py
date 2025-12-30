"""
Django Local Development Settings

Configuration for local development environment.
Uses SQLite database and local file storage.
"""
from .base import *
import logging

_secrets_logger = logging.getLogger('django.security.secrets')

# =============================================================================
# Core Settings
# =============================================================================
DEBUG = True
ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# =============================================================================
# Database Configuration
# =============================================================================
# Local SQLite database for development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# =============================================================================
# CORS Configuration
# =============================================================================
# Allow local frontend development server
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# =============================================================================
# Security Settings (Development - Less Restrictive)
# =============================================================================
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# =============================================================================
# CAPTCHA Configuration (Development)
# =============================================================================
# Disable CAPTCHA for easier local testing
CAPTCHA_ENABLED = False

# =============================================================================
# Email Configuration (Development)
# =============================================================================
# Use console backend for local development (emails printed to console)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
FRONTEND_URL = 'http://localhost:5173'

# Log email configuration
_secrets_logger.info(
    "Email backend: console (emails will be printed to console)"
)

# =============================================================================
# Static and Media Files
# =============================================================================
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Optional: Add static files directory if it exists
if (BASE_DIR / 'static').exists():
    STATICFILES_DIRS = [BASE_DIR / 'static']

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# =============================================================================
# Logging (Development)
# =============================================================================
# Update logging formatter to indicate local environment
LOGGING['formatters']['verbose'] = {
    'format': '[LOCAL] {levelname} {asctime} {module} {message}',
    'style': '{',
}

_secrets_logger.info("=" * 70)
_secrets_logger.info("ENVIRONMENT: Local Development")
_secrets_logger.info("Database: SQLite (db.sqlite3)")
_secrets_logger.info("CAPTCHA: Disabled")
_secrets_logger.info("=" * 70)
