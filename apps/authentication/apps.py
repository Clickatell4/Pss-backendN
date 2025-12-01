from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.authentication'

    def ready(self):
        """Import signals when app is ready (SCRUM-8: Authentication logging)"""
        import apps.authentication.signals  # noqa: F401
