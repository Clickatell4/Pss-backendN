from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    LoginView,
    LogoutView,
    CurrentUserView,
    RegisterView,
    CreateAdminView,
    CreateSuperuserView,
    PasswordResetRequestView,
    PasswordResetValidateTokenView,
    PasswordResetConfirmView,
    PasswordChangeView,
    # SCRUM-30: Session management views
    SessionListView,
    SessionDeleteView,
    SessionDeleteAllView,
    SessionDeleteAllExceptCurrentView,
    AdminSessionListView,
    AdminForceLogoutView,
    # SCRUM-14: Two-Factor Authentication views
    TwoFactorSetupView,
    TwoFactorVerifySetupView,
    TwoFactorDisableView,
    TwoFactorVerifyCodeView,
    BackupCodesRegenerateView,
)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('user/', CurrentUserView.as_view(), name='current_user'),
    path('me/', CurrentUserView.as_view(), name='current_user_alias'),  # Alias for backwards compatibility
    # Protected endpoints for creating privileged accounts
    path('create-admin/', CreateAdminView.as_view(), name='create_admin'),
    path('create-superuser/', CreateSuperuserView.as_view(), name='create_superuser'),
    # Password reset endpoints (SCRUM-117)
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset/validate-token/', PasswordResetValidateTokenView.as_view(), name='password_reset_validate'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # Password change endpoint for authenticated users (SCRUM-117)
    path('password-change/', PasswordChangeView.as_view(), name='password_change'),
    # Session management endpoints (SCRUM-30)
    # IMPORTANT: Place specific paths BEFORE parameterized paths to avoid routing conflicts
    path('sessions/', SessionListView.as_view(), name='session_list'),
    path('sessions/all/', SessionDeleteAllView.as_view(), name='session_delete_all'),
    path('sessions/all-except-current/', SessionDeleteAllExceptCurrentView.as_view(), name='session_delete_all_except_current'),
    path('sessions/<str:session_key>/', SessionDeleteView.as_view(), name='session_delete'),
    # Admin session management endpoints (SCRUM-30)
    path('admin/sessions/', AdminSessionListView.as_view(), name='admin_session_list'),
    path('admin/force-logout/', AdminForceLogoutView.as_view(), name='admin_force_logout'),
    # Two-Factor Authentication endpoints (SCRUM-14)
    path('2fa/setup/', TwoFactorSetupView.as_view(), name='2fa_setup'),
    path('2fa/verify-setup/', TwoFactorVerifySetupView.as_view(), name='2fa_verify_setup'),
    path('2fa/disable/', TwoFactorDisableView.as_view(), name='2fa_disable'),
    path('2fa/verify-code/', TwoFactorVerifyCodeView.as_view(), name='2fa_verify_code'),
    path('2fa/backup-codes/', BackupCodesRegenerateView.as_view(), name='2fa_backup_codes'),
]