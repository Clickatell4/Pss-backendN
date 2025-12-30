"""
Django settings module with environment-based configuration.

Uses DJANGO_ENVIRONMENT variable to load appropriate settings:
- 'local': Development on local machine
- 'testing': Staging/QA environment on Render
- 'production': Production environment on internal server
"""
import os
from decouple import config

ENVIRONMENT = config('DJANGO_ENVIRONMENT', default='local')

if ENVIRONMENT == 'production':
    from .production import *
elif ENVIRONMENT == 'testing':
    from .testing import *
else:
    from .local import *
