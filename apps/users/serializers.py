from rest_framework import serializers
from .models import User, UserProfile

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ('id', 'user',)
        read_only_fields = ('created_at', 'updated_at')

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'role', 'has_completed_intake', 'created_at', 'updated_at', 'profile')
        read_only_fields = ('id', 'has_completed_intake', 'created_at', 'updated_at')

    def validate_email(self, value):
        if not value.endswith('@capaciti.org.za'):
            raise serializers.ValidationError('Email must be a CAPACITI email address')
        return value
