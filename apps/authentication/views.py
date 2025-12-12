from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from apps.users.serializers import UserSerializer
from apps.users.permissions import IsSuperuser
from pss_backend.validators import sanitize_text, validate_email_domain, validate_text_length
from pss_backend.throttles import (
    AuthRateThrottle,
    RegisterRateThrottle,
    PasswordResetRequestThrottle,
    PasswordResetConfirmThrottle
)
from apps.authentication.models import PasswordResetToken
from apps.authentication.email_service import send_email

import logging

User = get_user_model()
logger = logging.getLogger("django.security.auth")

ADMIN_ALERT_EMAIL = "Seth.Valentine@capaciti.org.za"


# ============================================================================
# LOGIN
# ============================================================================
class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthRateThrottle]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({
                "detail": "Email and password are required",
                "errors": {
                    "email": ["This field is required."] if not email else [],
                    "password": ["This field is required."] if not password else [],
                },
            }, status=400)

        try:
            email = sanitize_text(email, max_length=255)
            email = validate_email_domain(email, allowed_domains=["capaciti.org.za"])
        except ValidationError as e:
            return Response({"detail": "Invalid email", "errors": {"email": [str(e)]}}, status=400)

        try:
            validate_text_length(password, max_length=128, field_name="Password")
        except ValidationError as e:
            return Response({"detail": "Invalid password", "errors": {"password": [str(e)]}}, status=400)

        user = authenticate(request, username=email, password=password)

        if user is None:
            send_email(
                subject="Security Alert – Failed Login Attempt",
                to=ADMIN_ALERT_EMAIL,
                template_name="admin_login_failed",
                context={"email": email},
            )
            return Response({"detail": "Invalid email or password"}, status=401)

        if not user.is_active:
            return Response({"detail": "Account is deactivated"}, status=401)

        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": UserSerializer(user).data,
        })


# ============================================================================
# LOGOUT
# ============================================================================
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token:
                RefreshToken(refresh_token).blacklist()
            return Response({"detail": "Successfully logged out"})
        except Exception:
            return Response({"detail": "Invalid token"}, status=400)


# ============================================================================
# CURRENT USER
# ============================================================================
class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)


# ============================================================================
# REGISTER USER
# ============================================================================
class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [RegisterRateThrottle]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        first_name = request.data.get("first_name", "")
        last_name = request.data.get("last_name", "")
        role = "candidate"

        if not email or not password:
            return Response({
                "error": "Email and password are required",
                "errors": {
                    "email": ["This field is required."] if not email else [],
                    "password": ["This field is required."] if not password else [],
                },
            }, status=400)

        try:
            email = sanitize_text(email, max_length=255)
            email = validate_email_domain(email, allowed_domains=["capaciti.org.za"])
        except ValidationError as e:
            return Response({"error": "Invalid email", "errors": {"email": [str(e)]}}, status=400)

        try:
            validate_text_length(password, min_length=8, max_length=128, field_name="Password")
            validate_password(password)
        except ValidationError as e:
            return Response({"error": "Invalid password", "errors": {"password": list(e.messages)}}, status=400)

        try:
            first_name = sanitize_text(first_name, max_length=150)
            last_name = sanitize_text(last_name, max_length=150)
        except ValidationError as e:
            return Response({"error": "Invalid name", "errors": {"name": [str(e)]}}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({"error": "User already exists", "errors": {"email": ["Email already in use"]}}, status=400)

        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role=role,
        )

        refresh = RefreshToken.for_user(user)

        send_email(
            subject="Welcome to PSS Platform!",
            to=user.email,
            template_name="welcome",
            context={"first_name": first_name},
        )

        send_email(
            subject="New User Registered",
            to=ADMIN_ALERT_EMAIL,
            template_name="admin_new_user",
            context={"email": user.email, "first_name": user.first_name, "last_name": user.last_name},
        )

        return Response({
            "user": UserSerializer(user).data,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }, status=201)


# ============================================================================
# ADMIN CREATION
# ============================================================================
class CreateAdminView(APIView):
    permission_classes = [IsSuperuser]

    def post(self, request):
        return Response({"detail": "Admin creation not modified in this ticket"})


class CreateSuperuserView(APIView):
    permission_classes = [IsSuperuser]

    def post(self, request):
        return Response({"detail": "Superuser creation not modified in this ticket"})


# ============================================================================
# PASSWORD RESET REQUEST
# ============================================================================
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetRequestThrottle]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response({"detail": "Email is required"}, status=400)

        try:
            email = sanitize_text(email, max_length=255)
            email = validate_email_domain(email, allowed_domains=["capaciti.org.za"])
        except ValidationError as e:
            return Response({"detail": "Invalid email", "errors": {"email": [str(e)]}}, status=400)

        try:
            user = User.objects.get(email=email, is_active=True)
            token_str, reset_token = PasswordResetToken.generate_token(
                user, request.META.get("REMOTE_ADDR"), request.META.get("HTTP_USER_AGENT", "")
            )

            send_email(
                subject="Password Reset Request",
                to=email,
                template_name="password_reset",
                context={"first_name": user.first_name, "token": token_str},
            )

            send_email(
                subject="Password Reset Requested",
                to=ADMIN_ALERT_EMAIL,
                template_name="admin_password_reset",
                context={"email": email},
            )

        except User.DoesNotExist:
            pass

        return Response({"message": "If the account exists, a reset link has been sent."})


# ============================================================================
# PASSWORD RESET CONFIRM
# ============================================================================
class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetConfirmThrottle]

    def post(self, request):
        token = request.data.get("token")
        new_password = request.data.get("new_password")

        if not token or not new_password:
            return Response({"detail": "Token and new password are required"}, status=400)

        try:
            validate_text_length(new_password, min_length=8, max_length=128, field_name="Password")
            validate_password(new_password)
        except ValidationError as e:
            return Response({"detail": "Invalid password", "errors": {"new_password": list(e.messages)}}, status=400)

        reset_token = PasswordResetToken.verify_token(token)
        if not reset_token:
            return Response({"detail": "Invalid or expired token"}, status=400)

        user = reset_token.user

        if user.check_password(new_password):
            return Response({"detail": "New password cannot be old password"}, status=400)

        user.set_password(new_password)
        user.save()

        reset_token.mark_as_used()
        OutstandingToken.objects.filter(user=user).delete()

        return Response({"message": "Password has been reset successfully."})
