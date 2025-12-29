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
]
