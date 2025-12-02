import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class StrongPasswordValidator:
    """
    Enforces password complexity:
    - Minimum 12 characters
    - At least one uppercase
    - At least one lowercase
    - At least one digit
    - At least one special character
    - Cannot contain user's name or email
    """

    def validate(self, password, user=None):

        if len(password) < 12:
            raise ValidationError(_("Password must be at least 12 characters long."))

        if not re.search(r"[A-Z]", password):
            raise ValidationError(_("Password must contain at least one uppercase letter."))

        if not re.search(r"[a-z]", password):
            raise ValidationError(_("Password must contain at least one lowercase letter."))

        if not re.search(r"\d", password):
            raise ValidationError(_("Password must contain at least one number."))

        if not re.search(r"[^\w\s]", password):
            raise ValidationError(_("Password must contain at least one special character."))

        if user:
            if user.email and user.email.split("@")[0].lower() in password.lower():
                raise ValidationError(_("Password cannot contain your email username."))

            if user.first_name and user.first_name.lower() in password.lower():
                raise ValidationError(_("Password cannot contain your first name."))

            if user.last_name and user.last_name.lower() in password.lower():
                raise ValidationError(_("Password cannot contain your last name."))

    def get_help_text(self):
        return _("Your password must include uppercase, lowercase, numbers, and special characters.")