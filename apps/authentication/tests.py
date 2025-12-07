"""
SCRUM-117: Password Reset and Change Tests
Comprehensive test suite for password reset and change functionality
"""
import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from datetime import timedelta
from apps.authentication.models import PasswordResetToken
from apps.users.popia_models import PasswordHistory

User = get_user_model()


@pytest.mark.django_db
class PasswordResetTestCase(APITestCase):
    """Test password reset request functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@capaciti.org.za',
            password='OldPassword123!',
            first_name='Test',
            last_name='User'
        )
        self.reset_url = '/api/auth/password-reset/request/'
        self.validate_url = '/api/auth/password-reset/validate-token/'
        self.confirm_url = '/api/auth/password-reset/confirm/'
    
    def test_password_reset_request_valid_email(self):
        """Test password reset request with valid email"""
        response = self.client.post(self.reset_url, {
            'email': 'test@capaciti.org.za'
        })
        
        assert response.status_code == status.HTTP_200_OK
        assert 'message' in response.data
        assert 'If an account with that email exists' in response.data['message']
        
        # Verify token was created
        assert PasswordResetToken.objects.filter(user=self.user).exists()
    
    def test_password_reset_request_nonexistent_email(self):
        """Test password reset request with non-existent email (should not reveal)"""
        response = self.client.post(self.reset_url, {
            'email': 'nonexistent@capaciti.org.za'
        })
        
        # Should return same response as valid email
        assert response.status_code == status.HTTP_200_OK
        assert 'If an account with that email exists' in response.data['message']
    
    def test_password_reset_request_missing_email(self):
        """Test password reset request without email"""
        response = self.client.post(self.reset_url, {})
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'email' in response.data['errors']
    
    def test_password_reset_token_validation(self):
        """Test token validation endpoint"""
        # Generate token
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        
        # Validate token
        response = self.client.post(self.validate_url, {
            'token': token_string
        })
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['valid'] is True
        assert response.data['email'] == self.user.email
    
    def test_password_reset_token_validation_invalid_token(self):
        """Test token validation with invalid token"""
        response = self.client.post(self.validate_url, {
            'token': 'invalid_token_string'
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['valid'] is False
    
    def test_password_reset_token_expired(self):
        """Test that expired tokens are invalid"""
        # Create token with past expiry
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        token_obj.expires_at = timezone.now() - timedelta(hours=2)
        token_obj.save()
        
        # Try to validate expired token
        response = self.client.post(self.validate_url, {
            'token': token_string
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['valid'] is False
    
    def test_password_reset_confirm_valid(self):
        """Test successful password reset"""
        # Generate token
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        
        # Reset password
        new_password = 'NewPassword123!@#'
        response = self.client.post(self.confirm_url, {
            'token': token_string,
            'new_password': new_password
        })
        
        assert response.status_code == status.HTTP_200_OK
        assert 'Password has been reset successfully' in response.data['message']
        
        # Verify token is marked as used
        token_obj.refresh_from_db()
        assert token_obj.used is True
        assert token_obj.used_at is not None
        
        # Verify user can login with new password
        self.user.refresh_from_db()
        assert self.user.check_password(new_password)
    
    def test_password_reset_confirm_same_password(self):
        """Test that password reset fails if new password is same as old"""
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        
        response = self.client.post(self.confirm_url, {
            'token': token_string,
            'new_password': 'OldPassword123!'
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'same as your old password' in response.data['detail']
    
    def test_password_reset_confirm_weak_password(self):
        """Test that weak passwords are rejected"""
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        
        # Too short password
        response = self.client.post(self.confirm_url, {
            'token': token_string,
            'new_password': 'short'
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'errors' in response.data
    
    def test_password_reset_token_single_use(self):
        """Test that tokens can only be used once"""
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        
        # First use - should succeed
        response1 = self.client.post(self.confirm_url, {
            'token': token_string,
            'new_password': 'NewPassword123!@#'
        })
        assert response1.status_code == status.HTTP_200_OK
        
        # Second use - should fail
        response2 = self.client.post(self.confirm_url, {
            'token': token_string,
            'new_password': 'AnotherPassword123!@#'
        })
        assert response2.status_code == status.HTTP_400_BAD_REQUEST
        assert 'Invalid, expired, or already used' in response2.data['detail']


@pytest.mark.django_db
class PasswordChangeTestCase(APITestCase):
    """Test password change for authenticated users"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@capaciti.org.za',
            password='OldPassword123!',
            first_name='Test',
            last_name='User'
        )
        
        # Authenticate user
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)
        
        self.change_url = '/api/auth/password-change/'
    
    def test_password_change_authenticated(self):
        """Test password change by authenticated user"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.client.post(self.change_url, {
            'old_password': 'OldPassword123!',
            'new_password': 'NewPassword123!@#'
        })
        
        assert response.status_code == status.HTTP_200_OK
        assert 'Password changed successfully' in response.data['message']
        
        # Verify password changed
        self.user.refresh_from_db()
        assert self.user.check_password('NewPassword123!@#')
    
    def test_password_change_unauthenticated(self):
        """Test that unauthenticated users cannot change password"""
        response = self.client.post(self.change_url, {
            'old_password': 'OldPassword123!',
            'new_password': 'NewPassword123!@#'
        })
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_password_change_wrong_old_password(self):
        """Test password change with wrong old password"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.client.post(self.change_url, {
            'old_password': 'WrongPassword123!',
            'new_password': 'NewPassword123!@#'
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'Old password is incorrect' in response.data['detail']
    
    def test_password_change_same_password(self):
        """Test that new password cannot be same as old"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.client.post(self.change_url, {
            'old_password': 'OldPassword123!',
            'new_password': 'OldPassword123!'
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'same as your old password' in response.data['detail']
    
    def test_password_change_weak_password(self):
        """Test that weak passwords are rejected"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.client.post(self.change_url, {
            'old_password': 'OldPassword123!',
            'new_password': 'weak'
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    def test_password_change_missing_fields(self):
        """Test password change with missing fields"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        response = self.client.post(self.change_url, {})
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'errors' in response.data
    
    def test_password_history_created(self):
        """Test that old password is added to history"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        
        old_password_hash = self.user.password
        
        response = self.client.post(self.change_url, {
            'old_password': 'OldPassword123!',
            'new_password': 'NewPassword123!@#'
        })
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify history entry created
        history = PasswordHistory.objects.filter(user=self.user)
        assert history.exists()
        assert history.first().password_hash == old_password_hash


@pytest.mark.django_db
class PasswordResetTokenModelTestCase(APITestCase):
    """Test PasswordResetToken model"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.user = User.objects.create_user(
            email='test@capaciti.org.za',
            password='TestPassword123!'
        )
    
    def test_generate_token(self):
        """Test token generation"""
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        
        # Verify token properties
        assert len(token_string) > 0
        assert token_obj.user == self.user
        assert token_obj.used is False
        assert token_obj.used_at is None
        assert token_obj.expires_at > timezone.now()
        
        # Verify token is hashed
        import hashlib
        token_hash = hashlib.sha256(token_string.encode()).hexdigest()
        assert token_obj.token_hash == token_hash
    
    def test_verify_token_valid(self):
        """Test token verification with valid token"""
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        
        verified_token = PasswordResetToken.verify_token(token_string)
        assert verified_token is not None
        assert verified_token.id == token_obj.id
    
    def test_verify_token_invalid(self):
        """Test token verification with invalid token"""
        verified_token = PasswordResetToken.verify_token('invalid_token')
        assert verified_token is None
    
    def test_verify_token_used(self):
        """Test that used tokens cannot be verified"""
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        token_obj.mark_as_used()
        
        verified_token = PasswordResetToken.verify_token(token_string)
        assert verified_token is None
    
    def test_verify_token_expired(self):
        """Test that expired tokens cannot be verified"""
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        token_obj.expires_at = timezone.now() - timedelta(hours=2)
        token_obj.save()
        
        verified_token = PasswordResetToken.verify_token(token_string)
        assert verified_token is None
    
    def test_mark_as_used(self):
        """Test marking token as used"""
        token_string, token_obj = PasswordResetToken.generate_token(self.user)
        
        token_obj.mark_as_used()
        
        assert token_obj.used is True
        assert token_obj.used_at is not None


# Run tests with: pytest apps/authentication/tests.py -v
