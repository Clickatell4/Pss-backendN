"""
SCRUM-11: POPIA/GDPR Compliance Serializers

Serializers for consent management, data export, and deletion requests.
"""
from rest_framework import serializers
from .popia_models import (
    PrivacyPolicyVersion,
    UserConsent,
    DataDeletionRequest,
    DataExportRequest
)
from pss_backend.validators import sanitize_text, validate_text_length


class PrivacyPolicyVersionSerializer(serializers.ModelSerializer):
    """Serializer for privacy policy versions"""

    class Meta:
        model = PrivacyPolicyVersion
        fields = [
            'id',
            'version',
            'title',
            'content',
            'effective_date',
            'is_active',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class UserConsentSerializer(serializers.ModelSerializer):
    """Serializer for user consent records"""
    consent_type_display = serializers.CharField(
        source='get_consent_type_display',
        read_only=True
    )
    privacy_policy_version_number = serializers.CharField(
        source='privacy_policy_version.version',
        read_only=True
    )

    class Meta:
        model = UserConsent
        fields = [
            'id',
            'consent_type',
            'consent_type_display',
            'privacy_policy_version',
            'privacy_policy_version_number',
            'granted',
            'granted_at',
            'withdrawn_at',
        ]
        read_only_fields = [
            'id',
            'granted_at',
            'withdrawn_at',
            'consent_type_display',
            'privacy_policy_version_number'
        ]


class ConsentGrantSerializer(serializers.Serializer):
    """Serializer for granting consent"""
    consent_type = serializers.ChoiceField(choices=UserConsent.CONSENT_TYPES)
    privacy_policy_version_id = serializers.IntegerField()
    ip_address = serializers.IPAddressField(required=False)
    user_agent = serializers.CharField(required=False, allow_blank=True)

    def validate_user_agent(self, value):
        if value:
            return sanitize_text(value, max_length=1000)
        return value


class DataDeletionRequestSerializer(serializers.ModelSerializer):
    """Serializer for data deletion requests"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    reviewed_by_email = serializers.EmailField(
        source='reviewed_by.email',
        read_only=True,
        allow_null=True
    )

    class Meta:
        model = DataDeletionRequest
        fields = [
            'id',
            'requested_at',
            'status',
            'status_display',
            'reason',
            'reviewed_by',
            'reviewed_by_email',
            'reviewed_at',
            'admin_notes',
            'completed_at',
        ]
        read_only_fields = [
            'id',
            'requested_at',
            'status',
            'status_display',
            'reviewed_by',
            'reviewed_by_email',
            'reviewed_at',
            'admin_notes',
            'completed_at',
        ]

    def validate_reason(self, value):
        if value:
            validate_text_length(value, max_length=5000, field_name='reason')
            return sanitize_text(value, max_length=5000)
        return value


class DataDeletionRequestCreateSerializer(serializers.Serializer):
    """Serializer for creating data deletion requests"""
    reason = serializers.CharField(required=False, allow_blank=True)

    def validate_reason(self, value):
        if value:
            validate_text_length(value, max_length=5000, field_name='reason')
            return sanitize_text(value, max_length=5000)
        return value


class DataDeletionRequestReviewSerializer(serializers.Serializer):
    """Serializer for admin review of deletion requests"""
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    notes = serializers.CharField(required=False, allow_blank=True)

    def validate_notes(self, value):
        if value:
            validate_text_length(value, max_length=2000, field_name='notes')
            return sanitize_text(value, max_length=2000)
        return value

    def validate(self, data):
        # Require notes when rejecting
        if data['action'] == 'reject' and not data.get('notes'):
            raise serializers.ValidationError({
                'notes': 'Rejection reason is required when rejecting a deletion request.'
            })
        return data


class DataExportRequestSerializer(serializers.ModelSerializer):
    """Serializer for data export requests"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = DataExportRequest
        fields = [
            'id',
            'requested_at',
            'status',
            'status_display',
            'completed_at',
            'download_count',
            'expires_at',
        ]
        read_only_fields = [
            'id',
            'requested_at',
            'status',
            'status_display',
            'completed_at',
            'download_count',
            'expires_at',
        ]
