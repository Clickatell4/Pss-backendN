from django.core.management.base import BaseCommand
from apps.users.models import User
import os


class Command(BaseCommand):
    help = 'Creates a superuser automatically from environment variables'

    def handle(self, *args, **options):
        email = os.environ.get('DJANGO_SUPERUSER_EMAIL')
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD')
        first_name = os.environ.get('DJANGO_SUPERUSER_FIRST_NAME', 'Admin')
        last_name = os.environ.get('DJANGO_SUPERUSER_LAST_NAME', 'User')

        if not email or not password:
            self.stdout.write(
                self.style.WARNING(
                    'Skipping superuser creation: DJANGO_SUPERUSER_EMAIL and '
                    'DJANGO_SUPERUSER_PASSWORD environment variables not set'
                )
            )
            return

        # Check if superuser already exists
        if User.objects.filter(email=email).exists():
            self.stdout.write(
                self.style.SUCCESS(f'Superuser with email {email} already exists')
            )
            return

        try:
            # Create superuser
            User.objects.create_superuser(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role='superuser'
            )
            self.stdout.write(
                self.style.SUCCESS(f'Superuser {email} created successfully!')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating superuser: {str(e)}')
            )