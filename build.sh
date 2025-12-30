#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Collect static files (no input required)
python manage.py collectstatic --no-input

# Run database migrations
python manage.py migrate --noinput

# Create superuser from environment variables (if not exists)
python manage.py create_superuser_auto
