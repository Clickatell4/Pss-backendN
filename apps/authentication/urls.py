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
]