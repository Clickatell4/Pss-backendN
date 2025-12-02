"""
Unit tests for User models
Tests user creation, password validation, and model methods
"""
import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from .factories import UserFactory, UserProfileFactory, PasswordHistoryFactory


@pytest.mark.django_db
class TestUserModel:
    """Tests for the User model."""

    def test_create_user_with_valid_email(self):
        """Test creating a user with a valid CAPACITI email."""
        user = UserFactory(email='test@capaciti.org.za')
        assert user.email == 'test@capaciti.org.za'
        assert user.role == 'candidate'
        assert user.is_active is True

    def test_create_user_with_invalid_email_domain(self):
        """Test that non-CAPACITI emails are rejected."""
        with pytest.raises(ValidationError, match='CAPACITI email'):
            user = UserFactory.build(email='test@gmail.com')
            user.full_clean()  # Trigger validation

    def test_user_password_hashing(self):
        """Test that passwords are properly hashed."""
        user = UserFactory(password='TestPass123!')
        assert user.password != 'TestPass123!'
        assert user.check_password('TestPass123!')

    def test_user_string_representation(self):
        """Test the __str__ method returns email."""
        user = UserFactory(email='john@capaciti.org.za')
        assert str(user) == 'john@capaciti.org.za'


@pytest.mark.django_db
class TestPasswordPolicy:
    """Tests for password policy (SCRUM-9)."""

    def test_weak_password_rejected(self):
        """Test that weak passwords are rejected."""
        with pytest.raises(ValidationError):
            UserFactory(
                email='weak@capaciti.org.za',
                password='password'  # Too weak
            )

    def test_short_password_rejected(self):
        """Test that passwords under 12 characters are rejected."""
        with pytest.raises(ValidationError, match='12 characters'):
            UserFactory(
                email='short@capaciti.org.za',
                password='Short1!'  # Only 7 characters
            )

    def test_password_without_uppercase_rejected(self):
        """Test that passwords without uppercase are rejected."""
        with pytest.raises(ValidationError, match='uppercase'):
            UserFactory(
                email='nouppercase@capaciti.org.za',
                password='lowercase123!'
            )

    def test_password_without_lowercase_rejected(self):
        """Test that passwords without lowercase are rejected."""
        with pytest.raises(ValidationError, match='lowercase'):
            UserFactory(
                email='nolowercase@capaciti.org.za',
                password='UPPERCASE123!'
            )

    def test_password_without_digit_rejected(self):
        """Test that passwords without digits are rejected."""
        with pytest.raises(ValidationError, match='number'):
            UserFactory(
                email='nodigit@capaciti.org.za',
                password='NoDigitPass!'
            )

    def test_password_without_special_char_rejected(self):
        """Test that passwords without special characters are rejected."""
        with pytest.raises(ValidationError, match='special character'):
            UserFactory(
                email='nospecial@capaciti.org.za',
                password='NoSpecial123'
            )

    def test_password_with_name_rejected(self):
        """Test that passwords containing user's name are rejected."""
        with pytest.raises(ValidationError, match='first name'):
            UserFactory(
                email='john@capaciti.org.za',
                first_name='John',
                password='JohnPassword123!'
            )

    def test_strong_password_accepted(self):
        """Test that a strong password is accepted."""
        user = UserFactory(
            email='strong@capaciti.org.za',
            password='MyStr0ng!Pass2024'
        )
        assert user.check_password('MyStr0ng!Pass2024')


@pytest.mark.django_db
class TestPasswordExpiry:
    """Tests for password expiry (SCRUM-9)."""

    def test_new_user_password_not_expired(self):
        """Test that newly created users have non-expired passwords."""
        user = UserFactory()
        assert not user.is_password_expired()

    def test_old_password_is_expired(self):
        """Test that 90+ day old passwords are expired."""
        user = UserFactory()
        # Set password_last_changed to 91 days ago
        user.password_last_changed = timezone.now() - timedelta(days=91)
        user.save()
        assert user.is_password_expired()

    def test_89_day_old_password_not_expired(self):
        """Test that 89-day old passwords are not expired."""
        user = UserFactory()
        user.password_last_changed = timezone.now() - timedelta(days=89)
        user.save()
        assert not user.is_password_expired()


@pytest.mark.django_db
class TestPasswordHistory:
    """Tests for password reuse prevention (SCRUM-9)."""

    def test_password_history_created_on_change(self):
        """Test that password history is created when password changes."""
        user = UserFactory(password='FirstPass123!')

        # Change password
        user.set_password('SecondPass123!')
        user.save()

        # Check history was created
        assert user.password_history.count() == 1

    def test_cannot_reuse_recent_password(self):
        """Test that recently used passwords cannot be reused."""
        user = UserFactory(password='FirstPass123!')

        # Change password
        user.set_password('SecondPass123!')
        user.save()

        # Try to change back to first password
        with pytest.raises(ValidationError, match='Cannot reuse'):
            user.set_password('FirstPass123!')
            user.save()

    def test_can_reuse_password_after_5_changes(self):
        """Test that passwords can be reused after 5 new passwords."""
        user = UserFactory(password='OriginalPass123!')

        # Change password 5 times
        for i in range(1, 6):
            user.set_password(f'NewPassword{i}23!')
            user.save()

        # Should be able to reuse original password now
        user.set_password('OriginalPass123!')
        user.save()
        assert user.check_password('OriginalPass123!')


@pytest.mark.django_db
class TestUserProfile:
    """Tests for UserProfile model."""

    def test_create_profile_with_user(self):
        """Test creating a user profile."""
        profile = UserProfileFactory()
        assert profile.user is not None
        assert profile.contact_number is not None

    def test_profile_string_representation(self):
        """Test profile __str__ method."""
        profile = UserProfileFactory(
            user__email='john@capaciti.org.za'
        )
        assert 'john@capaciti.org.za' in str(profile)

    def test_date_of_birth_calculated_from_id_number(self):
        """Test that DOB is calculated from SA ID number."""
        profile = UserProfileFactory(
            id_number='9501154800086'  # 15 Jan 1995
        )
        dob = profile.date_of_birth_calculated
        assert dob is not None
        assert dob.year == 1995
        assert dob.month == 1
        assert dob.day == 15

    def test_age_calculated_correctly(self):
        """Test that age is calculated correctly from ID number."""
        profile = UserProfileFactory(
            id_number='9501154800086'  # 15 Jan 1995
        )
        age = profile.age_calculated
        assert age is not None
        assert age >= 29  # At least 29 years old as of 2024


@pytest.mark.unit
@pytest.mark.security
def test_password_validator_import():
    """Test that custom password validator can be imported."""
    from apps.users.validators import StrongPasswordValidator

    validator = StrongPasswordValidator()
    assert validator is not None
    assert hasattr(validator, 'validate')
