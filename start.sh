#!/bin/bash
set -e

echo "Starting PSS Backend..."
echo "Running migrations..."
python manage.py migrate

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Creating superuser from environment variables (if configured)..."
python manage.py create_superuser_auto

echo "Starting Gunicorn server..."
exec gunicorn pss_backend.wsgi:application \
    --bind 0.0.0.0:$PORT \
    --workers 1 \
    --timeout 120 \
    --log-level info \
    --access-logfile - \
    --error-logfile -