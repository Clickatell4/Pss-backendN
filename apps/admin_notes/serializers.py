from rest_framework import serializers
from .models import AdminNote
from pss_backend.validators import (
    sanitize_text,
    validate_enum_choice,
    validate_text_length,
)


class AdminNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminNote
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at', 'admin')

    def validate_category(self, value):
        """Whitelist-based validation for category field"""
        return validate_enum_choice(
            value,
            AdminNote.CATEGORY_CHOICES,
            field_name='category'
        )

    def validate_title(self, value):
        """Sanitize and validate title"""
        if value:
            value = sanitize_text(value, max_length=200)
            validate_text_length(value, min_length=1, max_length=200, field_name='Title')
        return value

    def validate_content(self, value):
        """Sanitize and validate content"""
        if value:
            value = sanitize_text(value, max_length=10000)
            validate_text_length(value, min_length=1, max_length=10000, field_name='Content')
        return value
