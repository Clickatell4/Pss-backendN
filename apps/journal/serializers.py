from rest_framework import serializers
from .models import JournalEntry
from pss_backend.validators import (
    sanitize_text,
    validate_enum_choice,
    validate_positive_integer,
    validate_text_length,
)


class JournalEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = JournalEntry
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at', 'user')

    def validate_mood(self, value):
        """Whitelist-based validation for mood field"""
        return validate_enum_choice(
            value,
            JournalEntry.MOOD_CHOICES,
            field_name='mood'
        )

    def validate_energy_level(self, value):
        """Validate energy level is between 1-10"""
        return validate_positive_integer(
            value,
            max_value=10,
            field_name='energy_level'
        )

    def validate_activities(self, value):
        """Sanitize and validate activities text"""
        if value:
            value = sanitize_text(value, max_length=5000)
            validate_text_length(value, min_length=1, max_length=5000, field_name='Activities')
        return value

    def validate_challenges(self, value):
        """Sanitize challenges text"""
        if value:
            value = sanitize_text(value, max_length=5000)
        return value

    def validate_achievements(self, value):
        """Sanitize achievements text"""
        if value:
            value = sanitize_text(value, max_length=5000)
        return value

    def validate_notes(self, value):
        """Sanitize notes text"""
        if value:
            value = sanitize_text(value, max_length=10000)
        return value

    def validate_barriers_faced(self, value):
        """Sanitize barriers faced text"""
        if value:
            value = sanitize_text(value, max_length=5000)
        return value

    def validate_barrier_count(self, value):
        """Validate barrier count is non-negative"""
        if value is not None:
            return validate_positive_integer(
                value,
                max_value=100,
                field_name='barrier_count'
            )
        return value
