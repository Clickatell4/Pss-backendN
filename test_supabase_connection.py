#!/usr/bin/env python
"""
Test Supabase connection for testing environment.
This script loads .env.testing and tests both database and storage connections.
"""
import os
import sys
from pathlib import Path

# Add project to path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Load .env.testing manually
env_path = BASE_DIR / '.env.testing'
with open(env_path) as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            os.environ[key] = value

print("=" * 70)
print("Testing Supabase Connection")
print("=" * 70)

# Test 1: Check environment variables loaded
print("\n1. Environment Variables:")
print(f"   DJANGO_ENVIRONMENT: {os.getenv('DJANGO_ENVIRONMENT')}")
print(f"   SUPABASE_URL: {os.getenv('SUPABASE_URL')}")
print(f"   SUPABASE_KEY: {os.getenv('SUPABASE_KEY')[:20]}...")
print(f"   DATABASE_URL: postgresql://...{os.getenv('DATABASE_URL', '')[-30:]}")

# Test 2: Test Supabase client initialization
print("\n2. Testing Supabase Client:")
try:
    from supabase import create_client, Client

    supabase_url = os.getenv('SUPABASE_URL')
    supabase_key = os.getenv('SUPABASE_KEY')

    supabase: Client = create_client(supabase_url, supabase_key)
    print("   ✅ Supabase client created successfully")
except Exception as e:
    print(f"   ❌ Failed to create Supabase client: {e}")
    sys.exit(1)

# Test 3: Test storage bucket access
print("\n3. Testing Storage Bucket:")
try:
    bucket_name = os.getenv('SUPABASE_STORAGE_BUCKET', 'pss-testing-media')
    buckets = supabase.storage.list_buckets()

    bucket_exists = any(b.name == bucket_name for b in buckets)

    if bucket_exists:
        print(f"   ✅ Bucket '{bucket_name}' found")

        # Try to list files in bucket
        files = supabase.storage.from_(bucket_name).list()
        print(f"   ✅ Can access bucket (currently has {len(files)} files)")
    else:
        print(f"   ❌ Bucket '{bucket_name}' not found")
        print(f"   Available buckets: {[b.name for b in buckets]}")
except Exception as e:
    print(f"   ❌ Failed to access storage: {e}")

# Test 4: Test database connection
print("\n4. Testing Database Connection:")
try:
    import psycopg2
    from urllib.parse import urlparse

    db_url = os.getenv('DATABASE_URL')
    result = urlparse(db_url)

    conn = psycopg2.connect(
        database=result.path[1:],
        user=result.username,
        password=result.password,
        host=result.hostname,
        port=result.port
    )

    cursor = conn.cursor()
    cursor.execute('SELECT version();')
    db_version = cursor.fetchone()[0]

    print(f"   ✅ Connected to PostgreSQL")
    print(f"   Database version: {db_version[:50]}...")

    cursor.close()
    conn.close()

except Exception as e:
    print(f"   ❌ Failed to connect to database: {e}")

# Test 5: Test Django settings loading
print("\n5. Testing Django Settings:")
try:
    os.environ['DJANGO_SETTINGS_MODULE'] = 'pss_backend.settings'

    import django
    django.setup()

    from django.conf import settings

    print(f"   ✅ Django loaded successfully")
    print(f"   Environment: {os.getenv('DJANGO_ENVIRONMENT')}")
    print(f"   DEBUG: {settings.DEBUG}")
    print(f"   Database: {settings.DATABASES['default']['HOST']}")

except Exception as e:
    print(f"   ❌ Failed to load Django: {e}")

print("\n" + "=" * 70)
print("Connection test complete!")
print("=" * 70)
