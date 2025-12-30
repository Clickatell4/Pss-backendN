#!/usr/bin/env bash
# Render start script - runs migrations then starts Gunicorn

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Creating superuser (if configured)..."
python manage.py create_superuser_auto || echo "Superuser creation skipped or already exists"

echo "Starting Gunicorn..."
exec gunicorn pss_backend.wsgi:application
