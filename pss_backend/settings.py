# Custom authentication backend for email login
AUTHENTICATION_BACKENDS = [
    'apps.users.backends.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]

import os
from pathlib import Path
from datetime import timedelta
from decouple import config, Csv
import dj_database_url

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------------------
# SECURITY: STRICT ENV VALIDATION FOR PRODUCTION
# --------------------------------------------------------

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
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
    ),
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

# --------------------------------------------------------
# CORS
# --------------------------------------------------------
CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', cast=Csv(), default='http://localhost:5173')
CORS_ALLOW_CREDENTIALS = True

# --------------------------------------------------------
# SECURITY HEADERS
# --------------------------------------------------------
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", cast=bool, default=False)

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
        }
    }
}

# --------------------------------------------------------
# DEFAULT AUTO FIELD
# --------------------------------------------------------
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
