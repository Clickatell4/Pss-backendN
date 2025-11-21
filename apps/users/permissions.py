from rest_framework.permissions import BasePermission

class IsAdminOrSelf(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.role == 'admin':
            return True
        if hasattr(obj, 'id') and obj.id == request.user.id:
            return True
        if hasattr(obj, 'user') and obj.user.id == request.user.id:
            return True
        return False


class IsSuperuser(BasePermission):
    """
    Permission class that only allows superusers to access the view.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'superuser'


class IsAdmin(BasePermission):
    """
    Permission class that only allows admins to access the view.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'admin'


class IsAdminOrSuperuser(BasePermission):
    """
    Permission class that allows admins or superusers to access the view.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in ['admin', 'superuser']
