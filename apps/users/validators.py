"""
SCRUM-9: Custom password validators for strong password policy
Enforces OWASP-compliant password requirements
"""
import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class StrongPasswordValidator:
    """
    Enforces strong password complexity requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Cannot contain user's first name, last name, or email username

    Implements OWASP A07:2021 - Identification and Authentication Failures
    """

    def validate(self, password, user=None):
        """
        Validate password against complexity requirements.

        Args:
            password (str): The password to validate
            user (User, optional): User instance for personal info checking

        Raises:
            ValidationError: If password doesn't meet requirements
        """
        # Minimum length check
        if len(password) < 12:
            raise ValidationError(
                _("Password must be at least 12 characters long."),
                code='password_too_short',
            )

        # Uppercase letter check
        if not re.search(r"[A-Z]", password):
            raise ValidationError(
                _("Password must contain at least one uppercase letter."),
                code='password_no_upper',
            )

        # Lowercase letter check
        if not re.search(r"[a-z]", password):
            raise ValidationError(
                _("Password must contain at least one lowercase letter."),
                code='password_no_lower',
            )

        # Digit check
        if not re.search(r"\d", password):
            raise ValidationError(
                _("Password must contain at least one number."),
                code='password_no_digit',
            )

        # Special character check
        if not re.search(r"[^\w\s]", password):
            raise ValidationError(
                _("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)."),
                code='password_no_special',
            )

        # Personal info check (if user provided)
        if user:
            # Check against email username
            if user.email:
                email_username = user.email.split("@")[0].lower()
                if email_username and email_username in password.lower():
                    raise ValidationError(
                        _("Password cannot contain your email username."),
                        code='password_contains_email',
                    )

            # Check against first name
            if user.first_name and len(user.first_name) >= 3:
                if user.first_name.lower() in password.lower():
                    raise ValidationError(
                        _("Password cannot contain your first name."),
                        code='password_contains_first_name',
                    )

            # Check against last name
            if user.last_name and len(user.last_name) >= 3:
                if user.last_name.lower() in password.lower():
                    raise ValidationError(
                        _("Password cannot contain your last name."),
                        code='password_contains_last_name',
                    )

    def get_help_text(self):
        """Return help text for password requirements."""
        return _(
            "Your password must be at least 12 characters long and include "
            "uppercase letters, lowercase letters, numbers, and special characters."
        )
