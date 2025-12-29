from django.urls import path
from .views import (
    LoginView,
    LogoutView,
    CurrentUserView,
    RegisterView,
    CreateAdminView,
    CreateSuperuserView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    PasswordChangeView,
    PasswordResetValidateTokenView,
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
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("me/", CurrentUserView.as_view(), name="current-user"),
    path("register/", RegisterView.as_view(), name="register"),

    # Admin creation (simplified for this sprint)
    path("create-admin/", CreateAdminView.as_view(), name="create-admin"),
    path("create-superuser/", CreateSuperuserView.as_view(), name="create-superuser"),

    # Password reset
    path("password-reset/request/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password-reset/validate-token/", PasswordResetValidateTokenView.as_view(), name="password-reset-validate"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),

    # Password change endpoint for authenticated users
    path("password-change/", PasswordChangeView.as_view(), name="password-change"),

    # Session management endpoints (SCRUM-30)
    # IMPORTANT: Place specific paths BEFORE parameterized paths to avoid routing conflicts
    path("sessions/", SessionListView.as_view(), name="session-list"),
    path("sessions/all/", SessionDeleteAllView.as_view(), name="session-delete-all"),
    path("sessions/all-except-current/", SessionDeleteAllExceptCurrentView.as_view(), name="session-delete-all-except-current"),
    path("sessions/<str:session_key>/", SessionDeleteView.as_view(), name="session-delete"),

    # Admin session management endpoints (SCRUM-30)
    path("admin/sessions/", AdminSessionListView.as_view(), name="admin-session-list"),
    path("admin/force-logout/", AdminForceLogoutView.as_view(), name="admin-force-logout"),

    # Two-Factor Authentication endpoints (SCRUM-14)
    path("2fa/setup/", TwoFactorSetupView.as_view(), name="2fa-setup"),
    path("2fa/verify-setup/", TwoFactorVerifySetupView.as_view(), name="2fa-verify-setup"),
    path("2fa/disable/", TwoFactorDisableView.as_view(), name="2fa-disable"),
    path("2fa/verify-code/", TwoFactorVerifyCodeView.as_view(), name="2fa-verify-code"),
    path("2fa/backup-codes/", BackupCodesRegenerateView.as_view(), name="2fa-backup-codes"),
]
