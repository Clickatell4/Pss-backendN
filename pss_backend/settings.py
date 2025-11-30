# Custom authentication backend for email login
AUTHENTICATION_BACKENDS = [
    'apps.users.backends.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]

import os
import sys
import logging
from pathlib import Path
from datetime import timedelta
<<<<<<< HEAD
from decouple import config, Csv
import dj_database_url
=======
from decouple import config, Csv, UndefinedValueError

# =============================================================================
# Secrets Access Logging (SCRUM-26)
# =============================================================================
# Log when secrets are loaded at startup for audit trail
_secrets_logger = logging.getLogger('django.security.secrets')
>>>>>>> d7b02cf2b7903f35c4283c7b52b86f3fc94e64e3

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

<<<<<<< HEAD
# --------------------------------------------------------
# SECURITY: STRICT ENV VALIDATION FOR PRODUCTION
# --------------------------------------------------------
=======
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
>>>>>>> d7b02cf2b7903f35c4283c7b52b86f3fc94e64e3

# Default DEBUG is ALWAYS False (secure)
DEBUG = config("DEBUG", cast=bool, default=False)

# SECRET KEY must be provided in production
SECRET_KEY = config(
    "SECRET_KEY",
    default="django-insecure-development-key-only-for-testing"
)

# ALLOWED_HOSTS must be EXPLICITLY declared (no wildcard allowed)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv(), default=None)

if not DEBUG:
    # In production, ALLOWED_HOSTS cannot be empty or wildcard
    if not ALLOWED_HOSTS:
        raise ValueError("❌ ALLOWED_HOSTS must be set in production!")
    if "*" in ALLOWED_HOSTS:
        raise ValueError("❌ ALLOWED_HOSTS cannot contain '*'. This is insecure.")

else:
    # Local development convenience
    ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

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
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
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
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
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
<<<<<<< HEAD
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
    ),
=======
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
>>>>>>> d7b02cf2b7903f35c4283c7b52b86f3fc94e64e3
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
<<<<<<< HEAD
SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", cast=bool, default=False)

# --------------------------------------------------------
# LOGGING
# --------------------------------------------------------
LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(exist_ok=True)
=======
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
>>>>>>> d7b02cf2b7903f35c4283c7b52b86f3fc94e64e3

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
<<<<<<< HEAD
        }
    }
=======
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
    },
>>>>>>> d7b02cf2b7903f35c4283c7b52b86f3fc94e64e3
}

# --------------------------------------------------------
# DEFAULT AUTO FIELD
# --------------------------------------------------------
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
