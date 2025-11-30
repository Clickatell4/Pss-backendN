"""
SCRUM-11: POPIA/GDPR Compliance Views

API endpoints for:
- Data access rights (export user data)
- Right to be forgotten (data deletion requests)
- Consent management
- Privacy policy acceptance
"""
import json
from datetime import timedelta
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.db import transaction
from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import User, UserProfile
from .popia_models import (
    PrivacyPolicyVersion,
    UserConsent,
    DataDeletionRequest,
    DataExportRequest
)
from .popia_serializers import (
    PrivacyPolicyVersionSerializer,
    UserConsentSerializer,
    ConsentGrantSerializer,
    DataDeletionRequestSerializer,
    DataDeletionRequestCreateSerializer,
    DataDeletionRequestReviewSerializer,
    DataExportRequestSerializer,
)
from apps.journal.models import JournalEntry
from apps.admin_notes.models import AdminNote


class ActivePrivacyPolicyView(APIView):
    """
    Get the currently active privacy policy version.
    Public endpoint - no authentication required for transparency.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            active_policy = PrivacyPolicyVersion.objects.get(is_active=True)
            serializer = PrivacyPolicyVersionSerializer(active_policy)
            return Response(serializer.data)
        except PrivacyPolicyVersion.DoesNotExist:
            return Response(
                {'error': 'No active privacy policy found'},
                status=status.HTTP_404_NOT_FOUND
            )


class UserConsentListView(generics.ListAPIView):
    """
    List all consent records for the authenticated user.
    POPIA: Users have the right to know what consents they've given.
    """
    serializer_class = UserConsentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserConsent.objects.filter(user=self.request.user)


class GrantConsentView(APIView):
    """
    Grant consent for data processing.
    POPIA Chapter 2, Section 11: Lawful processing requires consent.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ConsentGrantSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data

        # Check if privacy policy version exists
        try:
            policy_version = PrivacyPolicyVersion.objects.get(
                id=validated_data['privacy_policy_version_id']
            )
        except PrivacyPolicyVersion.DoesNotExist:
            return Response(
                {'error': 'Invalid privacy policy version'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create or update consent record
        consent, created = UserConsent.objects.update_or_create(
            user=request.user,
            consent_type=validated_data['consent_type'],
            defaults={
                'privacy_policy_version': policy_version,
                'granted': True,
                'granted_at': timezone.now(),
                'withdrawn_at': None,
                'ip_address': validated_data.get('ip_address'),
                'user_agent': validated_data.get('user_agent', ''),
            }
        )

        response_serializer = UserConsentSerializer(consent)
        return Response(
            response_serializer.data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )


class WithdrawConsentView(APIView):
    """
    Withdraw consent for data processing.
    POPIA Chapter 2, Section 11(3): Right to withdraw consent.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, consent_id):
        try:
            consent = UserConsent.objects.get(id=consent_id, user=request.user)
        except UserConsent.DoesNotExist:
            return Response(
                {'error': 'Consent record not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        if not consent.granted:
            return Response(
                {'error': 'Consent already withdrawn'},
                status=status.HTTP_400_BAD_REQUEST
            )

        consent.withdraw()
        serializer = UserConsentSerializer(consent)
        return Response(serializer.data)


class DataExportView(APIView):
    """
    Export all user data in JSON format.
    POPIA Chapter 2, Section 18: Right to access personal information.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        # Create export request record
        export_request = DataExportRequest.objects.create(
            user=user,
            status='processing'
        )

        try:
            # Gather all user data
            export_data = self._gather_user_data(user)

            # Mark export as completed
            export_request.status = 'completed'
            export_request.completed_at = timezone.now()
            export_request.expires_at = timezone.now() + timedelta(hours=48)
            export_request.download_count += 1
            export_request.save()

            # Return JSON response
            response = HttpResponse(
                json.dumps(export_data, indent=2, default=str),
                content_type='application/json'
            )
            response['Content-Disposition'] = f'attachment; filename="my_data_{user.id}_{timezone.now().date()}.json"'
            return response

        except Exception as e:
            export_request.status = 'failed'
            export_request.error_message = str(e)
            export_request.save()

            return Response(
                {'error': 'Failed to export data', 'detail': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _gather_user_data(self, user):
        """
        Gather all personal data for the user.
        POPIA: Must include ALL personal information held.
        """
        data = {
            'export_metadata': {
                'exported_at': timezone.now().isoformat(),
                'user_id': user.id,
                'format': 'JSON',
                'popia_compliance': True,
            },
            'user_account': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role,
                'has_completed_intake': user.has_completed_intake,
                'is_active': user.is_active,
                'date_joined': user.date_joined.isoformat(),
                'created_at': user.created_at.isoformat(),
                'updated_at': user.updated_at.isoformat(),
            },
            'profile': None,
            'journal_entries': [],
            'admin_notes': [],
            'consents': [],
            'deletion_requests': [],
            'export_requests': [],
        }

        # Profile data (including encrypted PII)
        try:
            profile = user.profile
            data['profile'] = {
                'date_of_birth': profile.date_of_birth.isoformat() if profile.date_of_birth else None,
                'id_number': profile.id_number if profile.id_number else None,
                'contact_number': profile.contact_number,
                'address': profile.address,
                'emergency_contact': profile.emergency_contact if profile.emergency_contact else None,
                'emergency_phone': profile.emergency_phone if profile.emergency_phone else None,
                'diagnosis': profile.diagnosis if profile.diagnosis else None,
                'medications': profile.medications if profile.medications else None,
                'allergies': profile.allergies if profile.allergies else None,
                'medical_notes': profile.medical_notes if profile.medical_notes else None,
                'doctor_name': profile.doctor_name if profile.doctor_name else None,
                'doctor_phone': profile.doctor_phone if profile.doctor_phone else None,
                'accommodations': profile.accommodations,
                'assistive_technology': profile.assistive_technology,
                'learning_style': profile.learning_style,
                'support_needs': profile.support_needs,
                'communication_preferences': profile.communication_preferences,
                'created_at': profile.created_at.isoformat(),
                'updated_at': profile.updated_at.isoformat(),
            }
        except UserProfile.DoesNotExist:
            pass

        # Journal entries
        journal_entries = JournalEntry.objects.filter(user=user)
        data['journal_entries'] = [
            {
                'date': entry.date.isoformat(),
                'mood': entry.mood,
                'energy_level': entry.energy_level,
                'activities': entry.activities,
                'challenges': entry.challenges,
                'achievements': entry.achievements,
                'notes': entry.notes,
                'barriers_faced': entry.barriers_faced,
                'barrier_count': entry.barrier_count,
                'created_at': entry.created_at.isoformat(),
                'updated_at': entry.updated_at.isoformat(),
            }
            for entry in journal_entries
        ]

        # Admin notes about the user
        admin_notes = AdminNote.objects.filter(candidate=user)
        data['admin_notes'] = [
            {
                'category': note.category,
                'title': note.title,
                'content': note.content,
                'is_important': note.is_important,
                'created_by': note.admin.email,
                'created_at': note.created_at.isoformat(),
                'updated_at': note.updated_at.isoformat(),
            }
            for note in admin_notes
        ]

        # Consent records
        consents = UserConsent.objects.filter(user=user)
        data['consents'] = [
            {
                'consent_type': consent.consent_type,
                'granted': consent.granted,
                'privacy_policy_version': consent.privacy_policy_version.version,
                'granted_at': consent.granted_at.isoformat(),
                'withdrawn_at': consent.withdrawn_at.isoformat() if consent.withdrawn_at else None,
            }
            for consent in consents
        ]

        # Deletion requests
        deletion_requests = DataDeletionRequest.objects.filter(user=user)
        data['deletion_requests'] = [
            {
                'requested_at': req.requested_at.isoformat(),
                'status': req.status,
                'reason': req.reason,
                'reviewed_at': req.reviewed_at.isoformat() if req.reviewed_at else None,
            }
            for req in deletion_requests
        ]

        # Export requests
        export_requests = DataExportRequest.objects.filter(user=user)
        data['export_requests'] = [
            {
                'requested_at': req.requested_at.isoformat(),
                'status': req.status,
                'completed_at': req.completed_at.isoformat() if req.completed_at else None,
            }
            for req in export_requests
        ]

        return data


class DataDeletionRequestCreateView(APIView):
    """
    Create a data deletion request (Right to be Forgotten).
    POPIA Chapter 3, Section 16: Right to have personal information deleted.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = DataDeletionRequestCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already has a pending deletion request
        pending_request = DataDeletionRequest.objects.filter(
            user=request.user,
            status='pending'
        ).first()

        if pending_request:
            return Response(
                {
                    'error': 'You already have a pending deletion request',
                    'request_id': pending_request.id,
                    'requested_at': pending_request.requested_at,
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create deletion request
        deletion_request = DataDeletionRequest.objects.create(
            user=request.user,
            reason=serializer.validated_data.get('reason', '')
        )

        response_serializer = DataDeletionRequestSerializer(deletion_request)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class DataDeletionRequestListView(generics.ListAPIView):
    """
    List deletion requests.
    - Users can see their own requests
    - Admins can see all pending requests
    """
    serializer_class = DataDeletionRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role in ['admin', 'superuser']:
            # Admins see all requests
            return DataDeletionRequest.objects.all()
        else:
            # Users see only their own requests
            return DataDeletionRequest.objects.filter(user=user)


class DataDeletionRequestReviewView(APIView):
    """
    Admin endpoint to review (approve/reject) deletion requests.
    Only accessible to admin and superuser roles.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, request_id):
        # Check admin permission
        if request.user.role not in ['admin', 'superuser']:
            return Response(
                {'error': 'Only admins can review deletion requests'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get deletion request
        try:
            deletion_request = DataDeletionRequest.objects.get(id=request_id)
        except DataDeletionRequest.DoesNotExist:
            return Response(
                {'error': 'Deletion request not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Validate request is pending
        if deletion_request.status != 'pending':
            return Response(
                {'error': f'Request is already {deletion_request.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate input
        serializer = DataDeletionRequestReviewSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        action = serializer.validated_data['action']
        notes = serializer.validated_data.get('notes', '')

        # Process action
        if action == 'approve':
            deletion_request.approve(request.user, notes)
            # Note: Actual deletion would be done by a separate background job
            # to ensure proper data cleanup and retention compliance
        elif action == 'reject':
            deletion_request.reject(request.user, notes)

        response_serializer = DataDeletionRequestSerializer(deletion_request)
        return Response(response_serializer.data)


class ExecuteDataDeletionView(APIView):
    """
    Execute approved data deletion (admin only).
    POPIA: Must maintain audit trail even after deletion.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, request_id):
        # Check admin permission
        if request.user.role not in ['admin', 'superuser']:
            return Response(
                {'error': 'Only admins can execute deletions'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get deletion request
        try:
            deletion_request = DataDeletionRequest.objects.get(id=request_id)
        except DataDeletionRequest.DoesNotExist:
            return Response(
                {'error': 'Deletion request not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Validate request is approved
        if deletion_request.status != 'approved':
            return Response(
                {'error': 'Only approved requests can be executed'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Execute deletion
        try:
            deletion_summary = self._delete_user_data(deletion_request.user)
            deletion_request.complete(deletion_summary)

            return Response({
                'message': 'User data deleted successfully',
                'deletion_summary': deletion_summary,
            })
        except Exception as e:
            return Response(
                {'error': 'Failed to delete user data', 'detail': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @transaction.atomic
    def _delete_user_data(self, user):
        """
        Delete all user data while maintaining audit trail.
        POPIA: Keep deletion records for compliance proof.
        """
        deletion_summary = {
            'user_id': user.id,
            'email': user.email,
            'deleted_at': timezone.now().isoformat(),
            'items_deleted': {},
        }

        # Delete journal entries
        journal_count = JournalEntry.objects.filter(user=user).count()
        JournalEntry.objects.filter(user=user).delete()
        deletion_summary['items_deleted']['journal_entries'] = journal_count

        # Delete admin notes
        notes_count = AdminNote.objects.filter(candidate=user).count()
        AdminNote.objects.filter(candidate=user).delete()
        deletion_summary['items_deleted']['admin_notes'] = notes_count

        # Delete user profile
        try:
            user.profile.delete()
            deletion_summary['items_deleted']['profile'] = 1
        except UserProfile.DoesNotExist:
            deletion_summary['items_deleted']['profile'] = 0

        # Delete consents (keep deletion request for audit trail)
        consent_count = UserConsent.objects.filter(user=user).count()
        UserConsent.objects.filter(user=user).delete()
        deletion_summary['items_deleted']['consents'] = consent_count

        # Anonymize user account (soft delete - keep for referential integrity)
        user.email = f"deleted_{user.id}@deleted.local"
        user.first_name = "[DELETED]"
        user.last_name = "[DELETED]"
        user.is_active = False
        user.save()
        deletion_summary['user_anonymized'] = True

        return json.dumps(deletion_summary)
