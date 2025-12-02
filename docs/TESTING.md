# 🧪 Testing Guide - PSS Backend

Complete guide for writing and running tests in the PSS Backend Django application.

---

## 📚 Table of Contents

1. [Quick Start](#quick-start)
2. [Testing Stack](#testing-stack)
3. [Running Tests](#running-tests)
4. [Writing Tests](#writing-tests)
5. [Test Factories](#test-factories)
6. [Best Practices](#best-practices)
7. [CI/CD Pipeline](#cicd-pipeline)
8. [Troubleshooting](#troubleshooting)

---

## 🚀 Quick Start

### Install Testing Dependencies

```bash
# Activate virtual environment
source venv/bin/activate  # Mac/Linux
# or
venv\Scripts\activate  # Windows

# Install all dependencies including test packages
pip install -r requirements.txt
```

### Run All Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov

# Run specific test file
pytest apps/users/tests/test_models.py

# Run specific test
pytest apps/users/tests/test_models.py::TestUserModel::test_create_user_with_valid_email
```

### Run Tests by Marker

```bash
# Run only unit tests (fast)
pytest -m unit

# Run only integration tests
pytest -m integration

# Run only security tests
pytest -m security

# Run only POPIA compliance tests
pytest -m popia
```

---

## 🛠️ Testing Stack

| Tool | Purpose | Version |
|------|---------|---------|
| **pytest** | Test runner | 8.3.4 |
| **pytest-django** | Django integration for pytest | 4.9.0 |
| **pytest-cov** | Coverage reporting | 6.0.0 |
| **pytest-xdist** | Parallel test execution | 3.6.1 |
| **factory-boy** | Test data factories | 3.3.1 |
| **faker** | Fake data generation | 33.1.0 |
| **freezegun** | Time/date mocking | 1.5.1 |
| **responses** | HTTP mocking | 0.25.3 |

---

## 🏃 Running Tests

### Basic Commands

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov

# Run with HTML coverage report
pytest --cov --cov-report=html
# Open htmlcov/index.html in browser

# Run tests in parallel (faster)
pytest -n auto

# Run specific app tests
pytest apps/users/
pytest apps/authentication/

# Run and stop on first failure
pytest -x

# Run last failed tests only
pytest --lf

# Show print statements
pytest -s
```

### Advanced Options

```bash
# Run tests matching keyword
pytest -k "password"

# Run tests by marker
pytest -m "unit and security"

# Run with specific settings
pytest --ds=pss_backend.test_settings

# Reuse database (faster for reruns)
pytest --reuse-db

# Create new database each time
pytest --create-db

# Show slowest 10 tests
pytest --durations=10
```

---

## ✍️ Writing Tests

### Test File Structure

```
apps/
├── users/
│   └── tests/
│       ├── __init__.py
│       ├── factories.py          # Test data factories
│       ├── test_models.py         # Model tests
│       ├── test_views.py          # View/API tests
│       └── test_permissions.py    # Permission tests
└── authentication/
    └── tests/
        ├── __init__.py
        ├── test_views.py          # Auth endpoint tests
        └── test_security.py       # Security tests
```

### Example Unit Test

```python
"""apps/users/tests/test_models.py"""
import pytest
from .factories import UserFactory


@pytest.mark.django_db
class TestUserModel:
    """Tests for User model."""

    def test_create_user(self):
        """Test creating a user."""
        user = UserFactory(email='test@capaciti.org.za')
        assert user.email == 'test@capaciti.org.za'
        assert user.is_active is True

    def test_user_string_representation(self):
        """Test __str__ method."""
        user = UserFactory(email='john@capaciti.org.za')
        assert str(user) == 'john@capaciti.org.za'
```

### Example Integration Test

```python
"""apps/authentication/tests/test_views.py"""
import pytest
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse
from apps.users.tests.factories import UserFactory


@pytest.fixture
def api_client():
    return APIClient()


@pytest.mark.django_db
class TestLoginView:
    """Tests for login endpoint."""

    def test_login_success(self, api_client):
        """Test successful login."""
        user = UserFactory(
            email='test@capaciti.org.za',
            password='TestPass123!'
        )

        url = reverse('login')
        data = {
            'email': 'test@capaciti.org.za',
            'password': 'TestPass123!'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data
```

---

## 🏭 Test Factories

### Using Factories

```python
from apps.users.tests.factories import UserFactory, UserProfileFactory

# Create a user with defaults
user = UserFactory()

# Override specific fields
user = UserFactory(
    email='custom@capaciti.org.za',
    first_name='John',
    password='CustomPass123!'
)

# Create admin user
admin = UserFactory(role='admin', is_staff=True)

# Create user with profile
profile = UserProfileFactory()
user_with_profile = profile.user

# Create user with medical info
profile = UserProfileFactory(
    with_medical=True,
    diagnosis='Test diagnosis'
)

# Create multiple users
users = UserFactory.create_batch(5)
```

### Creating Custom Factories

```python
"""apps/myapp/tests/factories.py"""
import factory
from factory.django import DjangoModelFactory
from .models import MyModel


class MyModelFactory(DjangoModelFactory):
    class Meta:
        model = MyModel

    name = factory.Faker('name')
    email = factory.Sequence(lambda n: f'user{n}@capaciti.org.za')
    created_at = factory.Faker('date_time')
```

---

## ✅ Best Practices

### 1. Test Naming Convention

```python
# ✅ GOOD: Descriptive names
def test_user_cannot_login_with_wrong_password():
    ...

def test_password_reset_token_expires_after_one_hour():
    ...

# ❌ BAD: Vague names
def test_login():
    ...

def test_token():
    ...
```

### 2. Use Markers

```python
@pytest.mark.unit  # Fast, no database
def test_password_validator():
    ...

@pytest.mark.integration  # Database required
@pytest.mark.django_db
def test_user_creation():
    ...

@pytest.mark.security  # Security-focused
@pytest.mark.slow  # Takes time
def test_rate_limiting():
    ...
```

### 3. Test One Thing

```python
# ✅ GOOD: Single assertion
def test_user_email_is_lowercase():
    user = UserFactory(email='TEST@CAPACITI.ORG.ZA')
    assert user.email == 'test@capaciti.org.za'

# ❌ BAD: Testing multiple things
def test_user():
    user = UserFactory()
    assert user.email is not None
    assert user.is_active
    assert user.role == 'candidate'
    assert str(user) == user.email
```

### 4. Use Fixtures

```python
@pytest.fixture
def authenticated_client(api_client, user):
    """Fixture for authenticated API client."""
    api_client.force_authenticate(user=user)
    return api_client

@pytest.mark.django_db
def test_protected_endpoint(authenticated_client):
    """Test endpoint requires authentication."""
    url = reverse('protected-view')
    response = authenticated_client.get(url)
    assert response.status_code == 200
```

### 5. Test Security

```python
@pytest.mark.security
@pytest.mark.django_db
class TestSecurityFeatures:
    """Security-focused tests."""

    def test_passwords_are_hashed(self):
        """Ensure passwords are never stored in plaintext."""
        user = UserFactory(password='PlainText123!')
        assert user.password != 'PlainText123!'
        assert user.password.startswith('pbkdf2_sha256')

    def test_no_password_in_api_response(self, api_client):
        """Ensure password never returned in API."""
        url = reverse('current-user')
        # ... authenticate and get response
        assert 'password' not in response.data
```

### 6. Test POPIA Compliance

```python
@pytest.mark.popia
@pytest.mark.django_db
class TestPOPIACompliance:
    """POPIA compliance tests."""

    def test_pii_fields_are_encrypted(self):
        """Ensure PII is encrypted at rest."""
        profile = UserProfileFactory(
            id_number='9501154800086'
        )
        # Check database value is encrypted
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id_number FROM users_userprofile WHERE id=%s",
                [profile.id]
            )
            raw_value = cursor.fetchone()[0]
            assert raw_value != '9501154800086'
```

---

## 🔄 CI/CD Pipeline

### GitHub Actions

Tests run automatically on:
- Every push to `main` or `develop`
- Every pull request

### Pipeline Stages

1. **Checkout Code** - Get latest code
2. **Setup Python** - Install Python 3.11 & 3.12
3. **Install Dependencies** - `pip install -r requirements.txt`
4. **Lint Code** - Run flake8
5. **Run Tests** - Execute pytest with coverage
6. **Upload Coverage** - Send to Codecov

### View Test Results

```bash
# Check latest workflow run
gh run list

# View specific run
gh run view <run-id>

# View logs
gh run view <run-id> --log
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. `ModuleNotFoundError: No module named 'pytest'`

```bash
# Solution: Install test dependencies
pip install -r requirements.txt
```

#### 2. `django.core.exceptions.ImproperlyConfigured: SECRET_KEY`

```bash
# Solution: Set environment variable
export SECRET_KEY="test-key-for-local-testing"
pytest
```

#### 3. Tests using wrong database

```bash
# Solution: Specify test settings
pytest --ds=pss_backend.test_settings
```

#### 4. `FAILED apps/users/tests/test_models.py::test_password_validator - django.core.exceptions.ValidationError`

This is expected! The test is checking that weak passwords are rejected.

#### 5. Slow tests

```bash
# Solution 1: Run in parallel
pytest -n auto

# Solution 2: Reuse database
pytest --reuse-db

# Solution 3: Run only fast tests
pytest -m "not slow"
```

#### 6. ImportError with factories

```bash
# Ensure __init__.py exists in tests directories
touch apps/users/tests/__init__.py
touch apps/authentication/tests/__init__.py
```

---

## 📊 Coverage Goals

| Category | Target | Current |
|----------|--------|---------|
| **Overall** | 80%+ | TBD |
| **Models** | 90%+ | TBD |
| **Views** | 85%+ | TBD |
| **Security** | 95%+ | TBD |

---

## 📝 Test Checklist for New Features

When implementing a new feature, ensure you test:

- [ ] **Happy path** - Feature works as expected
- [ ] **Edge cases** - Boundary conditions
- [ ] **Error handling** - Invalid inputs
- [ ] **Permissions** - Authorization checks
- [ ] **Security** - No vulnerabilities introduced
- [ ] **POPIA** - Compliance maintained
- [ ] **Performance** - No N+1 queries
- [ ] **Integration** - Works with existing features

---

## 🎯 Quick Reference

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
pytest

# Run with coverage
pytest --cov

# Run specific tests
pytest apps/users/tests/test_models.py

# Run by marker
pytest -m unit
pytest -m integration
pytest -m security

# Run in parallel
pytest -n auto

# Rerun failed tests
pytest --lf

# View coverage report
pytest --cov --cov-report=html
open htmlcov/index.html
```

---

**Questions?** Check the main project documentation or ask in the team channel!
