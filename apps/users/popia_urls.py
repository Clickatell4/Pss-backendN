"""
SCRUM-11: POPIA/GDPR Compliance URL Routes

API endpoints for privacy compliance features.
"""
from django.urls import path
from .popia_views import (
    ActivePrivacyPolicyView,
    UserConsentListView,
    GrantConsentView,
    WithdrawConsentView,
    DataExportView,
    DataDeletionRequestCreateView,
    DataDeletionRequestListView,
    DataDeletionRequestReviewView,
    ExecuteDataDeletionView,
)

urlpatterns = [
    # Privacy Policy
    path('privacy-policy/', ActivePrivacyPolicyView.as_view(), name='active_privacy_policy'),

    # Consent Management
    path('consents/', UserConsentListView.as_view(), name='user_consents'),
    path('consents/grant/', GrantConsentView.as_view(), name='grant_consent'),
    path('consents/<int:consent_id>/withdraw/', WithdrawConsentView.as_view(), name='withdraw_consent'),

    # Data Access Rights (POPIA Section 18)
    path('data-export/', DataExportView.as_view(), name='data_export'),

    # Right to be Forgotten (POPIA Section 16)
    path('deletion-requests/', DataDeletionRequestListView.as_view(), name='deletion_request_list'),
    path('deletion-requests/create/', DataDeletionRequestCreateView.as_view(), name='deletion_request_create'),
    path('deletion-requests/<int:request_id>/review/', DataDeletionRequestReviewView.as_view(), name='deletion_request_review'),
    path('deletion-requests/<int:request_id>/execute/', ExecuteDataDeletionView.as_view(), name='deletion_request_execute'),
]
