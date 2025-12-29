# Custom authentication backend for email login
AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',  # SCRUM-10: Must be first for rate limiting
    'apps.users.backends.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]

import os
import sys
import logging
from pathlib import Path
from datetime import timedelta
from decouple import config, Csv, UndefinedValueError
import dj_database_url

# =============================================================================
# Secrets Access Logging (SCRUM-26)
# =============================================================================
# Log when secrets are loaded at startup for audit trail
_secrets_logger = logging.getLogger('django.security.secrets')

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# =============================================================================
# SECRET_KEY Configuration (CRITICAL SECURITY)
# =============================================================================
# SECRET_KEY is MANDATORY - Django will not start without it.
# Generate with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# List of known insecure/default keys that must be rejected
INSECURE_SECRET_KEYS = [
    'django-insecure-development-key-only-for-testing',
    'your-secret-key-here',
    'change-me',
    'secret',
    'django-insecure',
]

try:
    SECRET_KEY = config('SECRET_KEY')
except UndefinedValueError:
    raise RuntimeError(
        "\n\n"
        "=" * 70 + "\n"
        "CRITICAL ERROR: SECRET_KEY is not set!\n"
        "=" * 70 + "\n\n"
        "Django requires a SECRET_KEY to run securely.\n\n"
        "To fix this:\n"
        "1. Generate a key: python -c \"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\"\n"
        "2. Add to your .env file: SECRET_KEY=your-generated-key\n\n"
        "WARNING: Never commit your SECRET_KEY to version control!\n"
        "=" * 70 + "\n"
    )

# Validate SECRET_KEY
def _validate_secret_key(key):
    """Validate that SECRET_KEY meets security requirements."""
    errors = []

    # Check minimum length (Django recommends at least 50 characters)
    if len(key) < 50:
        errors.append(f"SECRET_KEY is too short ({len(key)} chars). Must be at least 50 characters.")

    # Check against known insecure keys
    if key.lower() in [k.lower() for k in INSECURE_SECRET_KEYS] or 'insecure' in key.lower():
        errors.append("SECRET_KEY contains a known insecure/default value.")

    if errors:
        raise RuntimeError(
            "\n\n"
            "=" * 70 + "\n"
            "CRITICAL ERROR: SECRET_KEY validation failed!\n"
            "=" * 70 + "\n\n"
            + "\n".join(f"  - {e}" for e in errors) + "\n\n"
            "To fix this:\n"
            "1. Generate a new key: python -c \"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\"\n"
            "2. Update your .env file with the new key\n\n"
            "=" * 70 + "\n"
        )

# Only validate SECRET_KEY in non-test environments
# Test environments need to use predictable keys for CI/CD
if not (os.getenv('DJANGO_SETTINGS_MODULE') == 'pss_backend.test_settings' or
        os.getenv('TESTING') == 'True'):
    _validate_secret_key(SECRET_KEY)

# Log successful SECRET_KEY load (without exposing the key)
_secrets_logger.info(
    "SECRET_KEY loaded successfully (length: %d, first 4 chars: %s...)",
    len(SECRET_KEY), SECRET_KEY[:4]
)

# =============================================================================
# Core Django Settings
# =============================================================================
DEBUG = config('DEBUG', cast=bool, default=False)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv(), default='localhost,127.0.0.1')

# Field-level encryption key for PII data (POPIA compliance)
# IMPORTANT: Generate a unique key for production using: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
FIELD_ENCRYPTION_KEY = config('FIELD_ENCRYPTION_KEY', default='dev-only-key-replace-in-production-32bytes!')

# Log encryption key status (SCRUM-26: secrets access logging)
if FIELD_ENCRYPTION_KEY == 'dev-only-key-replace-in-production-32bytes!':
    _secrets_logger.warning(
        "FIELD_ENCRYPTION_KEY is using default development value - NOT SAFE FOR PRODUCTION"
    )
else:
    _secrets_logger.info(
        "FIELD_ENCRYPTION_KEY loaded successfully (length: %d)",
        len(FIELD_ENCRYPTION_KEY)
    )

# --------------------------------------------------------
# APPLICATIONS
# --------------------------------------------------------
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third party
    'rest_framework',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'django_filters',
    'auditlog',  # SCRUM-8: Audit logging for compliance
    'axes',  # SCRUM-10: Rate limiting and brute force protection

    # Local apps
    'apps.authentication',
    'apps.users',
    'apps.intake',
    'apps.journal',
    'apps.admin_notes',
]

# --------------------------------------------------------
# MIDDLEWARE
# --------------------------------------------------------
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'pss_backend.middleware.RequestValidationMiddleware',  # SCRUM-7: Request validation
    'pss_backend.middleware.JSONValidationMiddleware',  # SCRUM-7: JSON validation
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.AxesMiddleware',  # SCRUM-10: Must be after AuthenticationMiddleware
    'auditlog.middleware.AuditlogMiddleware',  # SCRUM-8: Track who made changes
    'apps.authentication.middleware.SessionActivityMiddleware',  # SCRUM-30: Track session activity
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'pss_backend.urls'

# --------------------------------------------------------
# TEMPLATES
# --------------------------------------------------------
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'pss_backend.wsgi.application'

# --------------------------------------------------------
# DATABASE
# --------------------------------------------------------
DATABASE_URL = config('DATABASE_URL', default=None)

if DATABASE_URL:
    DATABASES = {
        'default': dj_database_url.parse(
            DATABASE_URL, conn_max_age=600, ssl_require=True
        )
    }
else:
    # Local development SQLite
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# --------------------------------------------------------
# PASSWORD VALIDATION
# --------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,  # SCRUM-9: Enforce minimum 12 characters
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'apps.users.validators.StrongPasswordValidator',  # SCRUM-9: Custom complexity validator
    },
]

# --------------------------------------------------------
# INTERNATIONALIZATION
# --------------------------------------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Johannesburg'
USE_I18N = True
USE_TZ = True

# --------------------------------------------------------
# STATIC + MEDIA
# --------------------------------------------------------
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

if (BASE_DIR / 'static').exists():
    STATICFILES_DIRS = [BASE_DIR / 'static']

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# --------------------------------------------------------
# CUSTOM USER MODEL
# --------------------------------------------------------
AUTH_USER_MODEL = 'users.User'

# --------------------------------------------------------
# REST FRAMEWORK
# --------------------------------------------------------
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': ('django_filters.rest_framework.DjangoFilterBackend',),
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '10/minute',
        'user': '1000/day',
    },
    # Custom exception handler for secure error responses (OWASP A05:2021)
    'EXCEPTION_HANDLER': 'pss_backend.exceptions.custom_exception_handler',
}

# --------------------------------------------------------
# SIMPLE JWT
# --------------------------------------------------------
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

# =============================================================================
# CAPTCHA CONFIGURATION (SCRUM-120 - Enhanced Brute Force Protection)
# =============================================================================
# Integrates with rate limiting (SCRUM-10) to add human verification layer

# Enable/disable CAPTCHA (useful for testing)
CAPTCHA_ENABLED = config('CAPTCHA_ENABLED', cast=bool, default=True)

# CAPTCHA provider ('recaptcha', 'hcaptcha', 'turnstile')
CAPTCHA_PROVIDER = config('CAPTCHA_PROVIDER', default='recaptcha')

# Failed attempts before requiring CAPTCHA (per IP + email combination)
CAPTCHA_TRIGGER_THRESHOLD = config('CAPTCHA_TRIGGER_THRESHOLD', cast=int, default=3)

# Cache timeout for failed login attempts (15 minutes)
CAPTCHA_FAILED_LOGIN_TIMEOUT = config('CAPTCHA_FAILED_LOGIN_TIMEOUT', cast=int, default=900)

# Google reCAPTCHA v3 Configuration
RECAPTCHA_PUBLIC_KEY = config('RECAPTCHA_PUBLIC_KEY', default='')
RECAPTCHA_PRIVATE_KEY = config('RECAPTCHA_PRIVATE_KEY', default='')
RECAPTCHA_REQUIRED_SCORE = config('RECAPTCHA_REQUIRED_SCORE', cast=float, default=0.5)  # 0.0-1.0

# Admin IPs that bypass CAPTCHA (optional - for internal tools)
CAPTCHA_BYPASS_IPS = config('CAPTCHA_BYPASS_IPS', cast=Csv(), default='')

# CAPTCHA applies to these actions
CAPTCHA_PROTECTED_ACTIONS = ['login', 'register', 'password_reset']

_secrets_logger.info(
    "CAPTCHA enabled: %s, provider: %s, trigger threshold: %d attempts",
    CAPTCHA_ENABLED, CAPTCHA_PROVIDER, CAPTCHA_TRIGGER_THRESHOLD
)
# =============================================================================

# =============================================================================
# CORS CONFIGURATION (SCRUM-41 — Harden Production CORS)
# =============================================================================

# ---- Allowed production origins (STRICT) ----
PRODUCTION_CORS_ORIGINS = [
    "https://pss-frontend-ebon.vercel.app",
]

# ---- Allowed development origins ----
DEVELOPMENT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# ---- Switch based on DEBUG mode ----
if DEBUG:
    CORS_ALLOWED_ORIGINS = DEVELOPMENT_CORS_ORIGINS
else:
    CORS_ALLOWED_ORIGINS = PRODUCTION_CORS_ORIGINS

# ---- Do NOT ever allow wildcard origins ----
CORS_ALLOW_ALL_ORIGINS = False

# ---- Allowed HTTP methods ----
CORS_ALLOWED_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
]

# ---- Allowed headers ----
CORS_ALLOWED_HEADERS = [
    "Authorization",
    "Content-Type",
    "Accept",
    "Origin",
    "User-Agent",
]

# ---- Whether cookies/JWT tokens can be sent ----
CORS_ALLOW_CREDENTIALS = True

# ---- Cache preflight (OPTIONS) responses ----
CORS_MAX_AGE = 86400  # 1 day
# =============================================================================

# --------------------------------------------------------
# SECURITY HEADERS
# --------------------------------------------------------
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', cast=bool, default=False)
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', cast=bool, default=False)
SECURE_HSTS_SECONDS = config('SECURE_HSTS_SECONDS', cast=int, default=0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = config('SECURE_HSTS_INCLUDE_SUBDOMAINS', cast=bool, default=False)
SECURE_HSTS_PRELOAD = config('SECURE_HSTS_PRELOAD', cast=bool, default=False)
X_FRAME_OPTIONS = 'DENY'

# CSRF Protection (OWASP A01:2021 - Broken Access Control)
CSRF_COOKIE_SECURE = config('CSRF_COOKIE_SECURE', cast=bool, default=False)
CSRF_COOKIE_HTTPONLY = True  # Prevent JavaScript access to CSRF cookie
CSRF_COOKIE_SAMESITE = 'Lax'  # Protect against CSRF while allowing normal navigation
CSRF_TRUSTED_ORIGINS = config('CSRF_TRUSTED_ORIGINS', cast=Csv(), default='http://localhost:5173,http://127.0.0.1:5173')

# Additional security headers
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'

# --------------------------------------------------------
# LOGGING
# --------------------------------------------------------
LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,

    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOG_DIR / 'django.log',
            'maxBytes': 1024 * 1024 * 10,
            'backupCount': 5,
            'level': 'WARNING',
        },
    },

    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
        # Secrets access logging (SCRUM-26)
        'django.security.secrets': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        # Authentication event logging (SCRUM-8)
        'django.security.auth': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# --------------------------------------------------------
# DEFAULT AUTO FIELD
# --------------------------------------------------------
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =============================================================================
# AUDIT LOGGING (SCRUM-8 - POPIA Compliance)
# =============================================================================
# Django Auditlog - Tracks all changes to sensitive data
# Required for POPIA compliance and security monitoring

# Log retention: 2 years minimum for POPIA compliance
# Note: Implement cleanup script for logs older than 2 years
# AUDITLOG_INCLUDE_TRACKING_MODELS = True  # Track all registered models

# Disable audit logging for select models (if needed)
# AUDITLOG_EXCLUDE_TRACKING_MODELS = ['SomeModel']

# =============================================================================

# =============================================================================
# RATE LIMITING & BRUTE FORCE PROTECTION (SCRUM-10)
# =============================================================================
# Django Axes - Authentication rate limiting and brute force protection
# Prevents credential stuffing and brute force attacks on login endpoints

# Lock out after 5 failed login attempts
AXES_FAILURE_LIMIT = 5

# Lockout duration: 15 minutes
AXES_COOLOFF_TIME = timedelta(minutes=15)

# Track by IP address and username combination
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True

# Also track IP-only failures (not just username+IP)
AXES_ONLY_USER_FAILURES = False

# Reset failed attempts on successful login
AXES_RESET_ON_SUCCESS = True

# Enable axes globally
AXES_ENABLED = True

# Log lockout attempts for security monitoring
AXES_VERBOSE = True

# Store in database (not cache) for persistence
AXES_HANDLER = 'axes.handlers.database.AxesDatabaseHandler'

# IP resolution order when behind proxy (e.g., Nginx)
AXES_META_PRECEDENCE_ORDER = [
    'HTTP_X_FORWARDED_FOR',
    'REMOTE_ADDR',
]

# Whitelist trusted IPs (none by default - add if needed)
AXES_NEVER_LOCKOUT_WHITELIST = []

# Use custom lockout response (will be JSON for API)
AXES_LOCKOUT_TEMPLATE = None  # Returns 403 JSON response
# =============================================================================

# =============================================================================
# EMAIL CONFIGURATION (SCRUM-117 - Password Reset)
# =============================================================================
# Email backend configuration for sending password reset emails
# Use console backend in development, SMTP in production

# Frontend URL for password reset links
FRONTEND_URL = config('FRONTEND_URL', default='http://localhost:5173')

# Email backend (console for dev, SMTP for production)
EMAIL_BACKEND = config(
    'EMAIL_BACKEND',
    default='django.core.mail.backends.console.EmailBackend'
)

# SMTP Configuration (only used if EMAIL_BACKEND is set to SMTP)
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', cast=int, default=587)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', cast=bool, default=True)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@capaciti.org.za')

# Log email configuration (without exposing credentials)
_secrets_logger.info(
    "Email backend: %s (SMTP host: %s, port: %s, from: %s)",
    EMAIL_BACKEND.split('.')[-1],
    EMAIL_HOST if EMAIL_BACKEND != 'django.core.mail.backends.console.EmailBackend' else 'N/A',
    EMAIL_PORT if EMAIL_BACKEND != 'django.core.mail.backends.console.EmailBackend' else 'N/A',
    DEFAULT_FROM_EMAIL
)

if EMAIL_BACKEND == 'django.core.mail.backends.console.EmailBackend':
    _secrets_logger.warning(
        "Using console email backend - emails will be printed to console (development only)"
    )
# =============================================================================

# =============================================================================
# INACTIVE ACCOUNT RETENTION (SCRUM-119 - POPIA Section 14)
# =============================================================================
# Automatic deletion of inactive accounts to comply with data minimization

# Inactivity threshold: Delete accounts after N years of no login
INACTIVE_ACCOUNT_THRESHOLD_YEARS = config('INACTIVE_ACCOUNT_THRESHOLD_YEARS', cast=int, default=2)

# Grace period: Days between first warning and deletion
INACTIVE_ACCOUNT_GRACE_PERIOD_DAYS = config('INACTIVE_ACCOUNT_GRACE_PERIOD_DAYS', cast=int, default=30)

# Roles exempt from automatic deletion
INACTIVE_ACCOUNT_EXCLUDE_ROLES = ['admin', 'superuser']

_secrets_logger.info(
    "Inactive account deletion: threshold=%d years, grace period=%d days",
    INACTIVE_ACCOUNT_THRESHOLD_YEARS, INACTIVE_ACCOUNT_GRACE_PERIOD_DAYS
)
# =============================================================================
