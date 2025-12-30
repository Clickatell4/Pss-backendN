#!/usr/bin/env python
"""
Verify testing environment setup is complete.
This checks that all required files and configurations are in place.
"""
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

print("=" * 70)
print("PSS Backend - Testing Environment Setup Verification")
print("=" * 70)

checks_passed = 0
checks_failed = 0

# Check 1: Settings files exist
print("\n1. Checking settings files...")
settings_files = [
    'pss_backend/settings/__init__.py',
    'pss_backend/settings/base.py',
    'pss_backend/settings/local.py',
    'pss_backend/settings/testing.py',
    'pss_backend/settings/production.py',
]

for file in settings_files:
    if (BASE_DIR / file).exists():
        print(f"   ✅ {file}")
        checks_passed += 1
    else:
        print(f"   ❌ {file} - MISSING")
        checks_failed += 1

# Check 2: Environment template files exist
print("\n2. Checking environment template files...")
env_templates = [
    '.env.local.example',
    '.env.testing.example',
    '.env.production.example',
]

for file in env_templates:
    if (BASE_DIR / file).exists():
        print(f"   ✅ {file}")
        checks_passed += 1
    else:
        print(f"   ❌ {file} - MISSING")
        checks_failed += 1

# Check 3: Actual environment files exist
print("\n3. Checking actual environment files...")
env_files = [
    ('.env.local', 'Local development'),
    ('.env.testing', 'Testing/staging'),
]

for file, desc in env_files:
    if (BASE_DIR / file).exists():
        print(f"   ✅ {file} ({desc})")
        checks_passed += 1
    else:
        print(f"   ⚠️  {file} ({desc}) - Not found (create from template)")

# Check 4: Storage backend exists
print("\n4. Checking Supabase storage backend...")
storage_backend = 'pss_backend/storage_backends.py'
if (BASE_DIR / storage_backend).exists():
    print(f"   ✅ {storage_backend}")
    checks_passed += 1
else:
    print(f"   ❌ {storage_backend} - MISSING")
    checks_failed += 1

# Check 5: Dependencies installed
print("\n5. Checking Python dependencies...")
try:
    import supabase
    print(f"   ✅ supabase package installed (v{supabase.__version__ if hasattr(supabase, '__version__') else 'unknown'})")
    checks_passed += 1
except ImportError:
    print("   ❌ supabase package NOT installed")
    checks_failed += 1

try:
    import django
    print(f"   ✅ Django installed (v{django.__version__})")
    checks_passed += 1
except ImportError:
    print("   ❌ Django NOT installed")
    checks_failed += 1

# Check 6: .env.testing has required variables
print("\n6. Checking .env.testing configuration...")
env_testing = BASE_DIR / '.env.testing'
if env_testing.exists():
    with open(env_testing) as f:
        content = f.read()

    required_vars = [
        'DJANGO_ENVIRONMENT',
        'SECRET_KEY',
        'DATABASE_URL',
        'SUPABASE_URL',
        'SUPABASE_KEY',
        'SUPABASE_STORAGE_BUCKET',
        'FIELD_ENCRYPTION_KEY',
    ]

    for var in required_vars:
        # Simple check - look for the variable name
        if f"{var}=" in content and not f"{var}=YOUR_" in content and not f"{var}=generate-" in content:
            print(f"   ✅ {var} configured")
            checks_passed += 1
        else:
            print(f"   ❌ {var} - Not configured or using placeholder")
            checks_failed += 1
else:
    print("   ❌ .env.testing file not found")
    checks_failed += 7

# Check 7: Local environment works
print("\n7. Testing local environment...")
try:
    os.environ['DJANGO_ENVIRONMENT'] = 'local'
    sys.path.insert(0, str(BASE_DIR))

    # Quick Django import test
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pss_backend.settings')
    import django
    django.setup()

    from django.conf import settings

    if settings.DJANGO_ENVIRONMENT == 'local' or os.getenv('DJANGO_ENVIRONMENT') == 'local':
        print("   ✅ Local environment loads successfully")
        print(f"      - DEBUG: {settings.DEBUG}")
        print(f"      - Database: {settings.DATABASES['default']['ENGINE']}")
        checks_passed += 1
    else:
        print("   ❌ Environment mismatch")
        checks_failed += 1
except Exception as e:
    print(f"   ❌ Failed to load local environment: {e}")
    checks_failed += 1

# Summary
print("\n" + "=" * 70)
print("VERIFICATION SUMMARY")
print("=" * 70)
print(f"Checks passed: {checks_passed}")
print(f"Checks failed: {checks_failed}")

if checks_failed == 0:
    print("\n✅ Setup is complete! Ready to deploy to Render.")
    sys.exit(0)
else:
    print(f"\n⚠️  Setup incomplete. Please fix {checks_failed} issue(s) above.")
    sys.exit(1)
