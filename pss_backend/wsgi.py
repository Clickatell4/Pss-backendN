import os
from django.core.wsgi import get_wsgi_application

# Use environment-specific settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE',
                      os.environ.get('DJANGO_SETTINGS_MODULE', 'pss_backend.settings.testing'))
application = get_wsgi_application()
