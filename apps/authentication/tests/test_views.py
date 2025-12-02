"""
Integration tests for authentication API endpoints
Tests login, logout, registration, and password reset flows
"""
import pytest
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse
from apps.users.tests.factories import UserFactory
from apps.authentication.models import PasswordResetToken


@pytest.fixture
def api_client():
    """Fixture for API client."""
    return APIClient()


@pytest.fixture
def user():
    """Fixture for a test user."""
    return UserFactory(
        email='testuser@capaciti.org.za',
        password='TestPass123!'
    )


@pytest.mark.django_db
class TestLoginView:
    """Tests for the login endpoint."""

    def test_login_with_valid_credentials(self, api_client, user):
        """Test successful login with valid credentials."""
        url = reverse('login')
        data = {
            'email': 'testuser@capaciti.org.za',
            'password': 'TestPass123!'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data
        assert 'user' in response.data

    def test_login_with_invalid_password(self, api_client, user):
        """Test login fails with wrong password."""
        url = reverse('login')
        data = {
            'email': 'testuser@capaciti.org.za',
            'password': 'WrongPassword123!'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert 'Invalid email or password' in str(response.data)

    def test_login_with_nonexistent_email(self, api_client):
        """Test login fails with non-existent email."""
        url = reverse('login')
        data = {
            'email': 'nonexistent@capaciti.org.za',
            'password': 'TestPass123!'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_with_inactive_user(self, api_client, user):
        """Test login fails for inactive users."""
        user.is_active = False
        user.save()

        url = reverse('login')
        data = {
            'email': 'testuser@capaciti.org.za',
            'password': 'TestPass123!'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_missing_email(self, api_client):
        """Test login fails when email is missing."""
        url = reverse('login')
        data = {'password': 'TestPass123!'}

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_missing_password(self, api_client):
        """Test login fails when password is missing."""
        url = reverse('login')
        data = {'email': 'testuser@capaciti.org.za'}

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestRegisterView:
    """Tests for the registration endpoint."""

    def test_register_with_valid_data(self, api_client):
        """Test successful registration with valid data."""
        url = reverse('register')
        data = {
            'email': 'newuser@capaciti.org.za',
            'password': 'NewUserPass123!',
            'first_name': 'New',
            'last_name': 'User'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert 'access' in response.data
        assert 'refresh' in response.data
        assert response.data['user']['email'] == 'newuser@capaciti.org.za'
        assert response.data['user']['role'] == 'candidate'

    def test_register_with_weak_password(self, api_client):
        """Test registration fails with weak password."""
        url = reverse('register')
        data = {
            'email': 'newuser@capaciti.org.za',
            'password': 'weak',
            'first_name': 'New',
            'last_name': 'User'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_with_duplicate_email(self, api_client, user):
        """Test registration fails with existing email."""
        url = reverse('register')
        data = {
            'email': 'testuser@capaciti.org.za',  # Already exists
            'password': 'NewUserPass123!',
            'first_name': 'Duplicate',
            'last_name': 'User'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'already exists' in str(response.data)

    def test_register_with_invalid_email_domain(self, api_client):
        """Test registration fails with non-CAPACITI email."""
        url = reverse('register')
        data = {
            'email': 'newuser@gmail.com',
            'password': 'NewUserPass123!',
            'first_name': 'New',
            'last_name': 'User'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_creates_candidate_role_only(self, api_client):
        """Test that public registration only creates candidate accounts."""
        url = reverse('register')
        data = {
            'email': 'newuser@capaciti.org.za',
            'password': 'NewUserPass123!',
            'first_name': 'New',
            'last_name': 'User'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['user']['role'] == 'candidate'
        assert response.data['user']['is_staff'] is False


@pytest.mark.django_db
class TestLogoutView:
    """Tests for the logout endpoint."""

    def test_logout_with_valid_token(self, api_client, user):
        """Test successful logout with valid refresh token."""
        # First login to get tokens
        login_url = reverse('login')
        login_data = {
            'email': 'testuser@capaciti.org.za',
            'password': 'TestPass123!'
        }
        login_response = api_client.post(login_url, login_data, format='json')
        refresh_token = login_response.data['refresh']

        # Now logout
        logout_url = reverse('logout')
        logout_data = {'refresh': refresh_token}
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')

        response = api_client.post(logout_url, logout_data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'logged out' in str(response.data).lower()


@pytest.mark.django_db
class TestPasswordResetFlow:
    """Tests for password reset functionality (SCRUM-117)."""

    def test_password_reset_request_with_valid_email(self, api_client, user):
        """Test password reset request with existing email."""
        url = reverse('password_reset_request')
        data = {'email': 'testuser@capaciti.org.za'}

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert PasswordResetToken.objects.filter(user=user).exists()

    def test_password_reset_request_with_nonexistent_email(self, api_client):
        """Test password reset request with non-existent email (no enumeration)."""
        url = reverse('password_reset_request')
        data = {'email': 'nonexistent@capaciti.org.za'}

        response = api_client.post(url, data, format='json')

        # Should return success to prevent email enumeration
        assert response.status_code == status.HTTP_200_OK
        assert PasswordResetToken.objects.count() == 0

    def test_password_reset_validate_token(self, api_client, user):
        """Test token validation endpoint."""
        # Create a reset token
        token_string, token_obj = PasswordResetToken.generate_token(user)

        url = reverse('password_reset_validate_token')
        data = {'token': token_string}

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['valid'] is True

    def test_password_reset_validate_invalid_token(self, api_client):
        """Test validation with invalid token."""
        url = reverse('password_reset_validate_token')
        data = {'token': 'invalid-token'}

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['valid'] is False

    def test_password_reset_confirm_with_valid_token(self, api_client, user):
        """Test password reset confirmation with valid token."""
        # Create a reset token
        token_string, token_obj = PasswordResetToken.generate_token(user)

        url = reverse('password_reset_confirm')
        data = {
            'token': token_string,
            'new_password': 'NewStrongPass123!'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK

        # Verify password was changed
        user.refresh_from_db()
        assert user.check_password('NewStrongPass123!')

        # Verify token was marked as used
        token_obj.refresh_from_db()
        assert token_obj.used is True


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.django_db
class TestAuthenticationSecurity:
    """Security-focused tests for authentication."""

    def test_password_not_returned_in_responses(self, api_client):
        """Test that password hashes are never returned in API responses."""
        url = reverse('register')
        data = {
            'email': 'secure@capaciti.org.za',
            'password': 'SecurePass123!',
            'first_name': 'Secure',
            'last_name': 'User'
        }

        response = api_client.post(url, data, format='json')

        assert 'password' not in response.data['user']
        assert 'SecurePass123!' not in str(response.data)

    def test_rate_limiting_prevents_brute_force(self, api_client, settings):
        """Test that rate limiting is configured (logic test only)."""
        # This tests that throttle classes are configured
        # Actual rate limit testing would require many requests
        from pss_backend.throttles import AuthRateThrottle

        throttle = AuthRateThrottle()
        assert throttle.rate is not None
