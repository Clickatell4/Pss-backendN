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
