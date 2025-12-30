#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Collect static files (no input required)
python manage.py collectstatic --no-input

# Note: Migrations will run automatically on first request via release command
# Render's build environment can't connect to external databases
echo "Build completed successfully. Migrations will run on startup."
