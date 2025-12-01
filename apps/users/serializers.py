from rest_framework import serializers
from .models import User, UserProfile
from pss_backend.validators import (
    sanitize_text,
    validate_phone_number,
    validate_id_number,
    validate_email_domain,
    validate_enum_choice,
    validate_text_length,
)


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ('id', 'user',)
        read_only_fields = ('created_at', 'updated_at')

    def validate_id_number(self, value):
        """Validate South African ID number format"""
        if value:
            return validate_id_number(value)
        return value

    def validate_contact_number(self, value):
        """Validate phone number format"""
        if value:
            return validate_phone_number(value)
        return value

    def validate_emergency_phone(self, value):
        """Validate emergency contact phone number"""
        if value:
            return validate_phone_number(value)
        return value

    def validate_doctor_phone(self, value):
        """Validate doctor phone number"""
        if value:
            return validate_phone_number(value)
        return value

    def validate_address(self, value):
        """Sanitize and validate address"""
        if value:
            value = sanitize_text(value, max_length=500)
            validate_text_length(value, max_length=500, field_name='Address')
        return value

    def validate_emergency_contact(self, value):
        """Sanitize emergency contact name"""
        if value:
            value = sanitize_text(value, max_length=255)
            validate_text_length(value, max_length=255, field_name='Emergency contact')
        return value

    def validate_diagnosis(self, value):
        """Sanitize diagnosis (encrypted field)"""
        if value:
            value = sanitize_text(value, max_length=5000)
        return value

    def validate_medications(self, value):
        """Sanitize medications list (encrypted field)"""
        if value:
            value = sanitize_text(value, max_length=5000)
        return value

    def validate_allergies(self, value):
        """Sanitize allergies list (encrypted field)"""
        if value:
            value = sanitize_text(value, max_length=5000)
        return value

    def validate_medical_notes(self, value):
        """Sanitize medical notes (encrypted field)"""
        if value:
            value = sanitize_text(value, max_length=10000)
        return value

    def validate_doctor_name(self, value):
        """Sanitize doctor name (encrypted field)"""
        if value:
            value = sanitize_text(value, max_length=255)
        return value

    def validate_accommodations(self, value):
        """Sanitize accommodations text"""
        if value:
            value = sanitize_text(value, max_length=2000)
        return value

    def validate_assistive_technology(self, value):
        """Sanitize assistive technology description"""
        if value:
            value = sanitize_text(value, max_length=2000)
        return value

    def validate_learning_style(self, value):
        """Sanitize learning style"""
        if value:
            value = sanitize_text(value, max_length=100)
        return value

    def validate_support_needs(self, value):
        """Sanitize support needs"""
        if value:
            value = sanitize_text(value, max_length=2000)
        return value

    def validate_communication_preferences(self, value):
        """Sanitize communication preferences"""
        if value:
            value = sanitize_text(value, max_length=2000)
        return value


class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'role', 'has_completed_intake', 'created_at', 'updated_at', 'profile')
        read_only_fields = ('id', 'has_completed_intake', 'created_at', 'updated_at')

    def validate_email(self, value):
        """Validate email domain (CAPACITI only)"""
        return validate_email_domain(value, allowed_domains=['capaciti.org.za'])

    def validate_first_name(self, value):
        """Sanitize and validate first name"""
        if value:
            value = sanitize_text(value, max_length=150)
            validate_text_length(value, max_length=150, field_name='First name')
        return value

    def validate_last_name(self, value):
        """Sanitize and validate last name"""
        if value:
            value = sanitize_text(value, max_length=150)
            validate_text_length(value, max_length=150, field_name='Last name')
        return value

    def validate_role(self, value):
        """Whitelist-based validation for role field"""
        if value:
            return validate_enum_choice(
                value,
                User.ROLE_CHOICES,
                field_name='role'
            )
        return value
