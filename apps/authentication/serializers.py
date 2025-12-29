"""
SCRUM-117: Password Reset and Change Serializers
Handles validation for password reset, confirmation, and password change operations
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

User = get_user_model()


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request endpoint.
    Only requires email address (validation happens in view).
    """
    email = serializers.EmailField(required=True)


class PasswordResetValidateTokenSerializer(serializers.Serializer):
    """
    Serializer for password reset token validation.
    Frontend uses this to check if token is valid before showing reset form.
    """
    token = serializers.CharField(required=True)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation.
    Validates token and new password.
    """
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        max_length=128
    )


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for authenticated user password change.
    Requires old password (for verification) and new password.
    
    Security:
    - Old password must be correct (prevents account takeover if session hijacked)
    - New password goes through Django's password validators
    - Cannot be same as old password
    """
    old_password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=1,
        max_length=128
    )
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        max_length=128
    )
    
    def validate_old_password(self, value):
        """Verify old password is correct"""
        user = self.context.get('user')
        if not user:
            raise ValidationError("User not found in context")
        
        if not user.check_password(value):
            raise ValidationError("Old password is incorrect")
        
        return value
    
    def validate_new_password(self, value):
        """
        Validate new password against Django's validators.
        This checks:
        - Minimum length requirements
        - Common password list
        - Numeric-only passwords
        - Too similar to user info
        """
        user = self.context.get('user')
        if user:
            try:
                validate_password(value, user=user)
            except ValidationError as e:
                raise ValidationError(list(e.messages))
        return value
    
    def validate(self, data):
        """Cross-field validation"""
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        
        user = self.context.get('user')
        
        # Check if new password is same as old password
        if user and user.check_password(new_password):
            raise ValidationError({
                'new_password': 'New password cannot be the same as your old password'
            })
        
        return data
