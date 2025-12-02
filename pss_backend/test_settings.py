"""
Test settings for PSS Backend
Optimized for fast test execution with in-memory SQLite database
"""
import os

# Set SECRET_KEY BEFORE importing settings to bypass validation
# This ensures tests can run with a known test key
os.environ.setdefault(
    'SECRET_KEY',
    'django-insecure-test-key-for-testing-purposes-only-do-not-use-in-production-12345678'
)

from .settings import *  # noqa: F403, E402

# Use fast password hasher for tests (speeds up user creation)
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Use in-memory SQLite for tests (fastest option)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable migrations for tests (use schema directly)
class DisableMigrations:
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None

# Comment this out if you need to test migrations specifically
# MIGRATION_MODULES = DisableMigrations()

# Disable debug mode in tests
DEBUG = False

# Use simple email backend for tests (no actual emails sent)
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Disable CAPTCHA for tests
CAPTCHA_ENABLED = False

# Disable rate limiting for tests (use @override_settings to re-enable)
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] = {  # noqa: F405
    'anon': '1000/minute',
    'user': '1000/minute',
    'auth': '1000/minute',
    'register': '1000/minute',
}

# Use valid Fernet encryption key for tests
# Generated with: python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
FIELD_ENCRYPTION_KEY = 'Hg8lygq6UnHNsSOOxj1T7KvFqlI6xhxso5ERVVLXGBI='

# Disable Axes lockout for tests
AXES_ENABLED = False

# Simpler logging for tests
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
}

# Allow all hosts in tests
ALLOWED_HOSTS = ['*']

# Test-specific settings
TEST_MODE = True
