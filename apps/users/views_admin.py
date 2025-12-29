from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from rest_framework import permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

User = get_user_model()


class CanManageUsers(permissions.BasePermission):
    """
    Allows access only to users with user management permissions
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.has_perm("users.change_user")
        )


@api_view(["PATCH"])
@permission_classes([CanManageUsers])
def activate_user(request, user_id):
    if request.user.id == user_id:
        return Response(
            {"detail": "You cannot activate your own account."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = User.objects.get(id=user_id)
    user.is_active = True
    user.save()

    return Response({"status": "activated"})


@api_view(["PATCH"])
@permission_classes([CanManageUsers])
def deactivate_user(request, user_id):
    if request.user.id == user_id:
        return Response(
            {"detail": "You cannot deactivate your own account."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if user.is_superuser:
        return Response(
            {"detail": "Superusers cannot be deactivated."},
            status=status.HTTP_403_FORBIDDEN,
        )

    user = User.objects.get(id=user_id)
    user.is_active = False
    user.save()

    return Response({"status": "deactivated"})
