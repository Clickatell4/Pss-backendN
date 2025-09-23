#!/usr/bin/env bash
# Start script for Render deployment

set -o errexit  # Exit on any error

echo "Starting PSS Backend..."

# Run any pending migrations (in case they weren't run in build)
echo "Ensuring database is up to date..."
python manage.py migrate --no-input

# Create superuser if it doesn't exist (optional)
if [ "$DJANGO_SUPERUSER_EMAIL" ] && [ "$DJANGO_SUPERUSER_PASSWORD" ]; then
    echo "Creating superuser if it doesn't exist..."
    python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='$DJANGO_SUPERUSER_EMAIL').exists():
    User.objects.create_superuser(
        email='$DJANGO_SUPERUSER_EMAIL',
        password='$DJANGO_SUPERUSER_PASSWORD',
        first_name='Admin',
        last_name='User'
    )
    print('Superuser created')
else:
    print('Superuser already exists')
"
fi

# Start the application with gunicorn
echo "Starting Gunicorn server..."
exec gunicorn --config gunicorn.conf.py pss_backend.wsgi:application