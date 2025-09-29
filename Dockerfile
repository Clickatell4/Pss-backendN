# Use Python 3.11.9 official image
FROM python:3.11.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

# Copy project files
COPY . /app/

# Create necessary directories
RUN mkdir -p /app/staticfiles /app/logs

# Collect static files (allow failure in case of missing SECRET_KEY)
RUN python manage.py collectstatic --noinput || echo "Static files collection failed - will retry at runtime"

# Expose port
EXPOSE $PORT

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:$PORT/api/ || exit 1

# Start command
CMD ["sh", "-c", "python manage.py migrate && python manage.py collectstatic --noinput && gunicorn pss_backend.wsgi:application --bind 0.0.0.0:$PORT --workers 1 --timeout 300 --keep-alive 2 --max-requests 1000 --max-requests-jitter 50"]