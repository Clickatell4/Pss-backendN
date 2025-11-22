from rest_framework import generics, permissions
from rest_framework.exceptions import PermissionDenied
from .models import AdminNote
from .serializers import AdminNoteSerializer
from apps.users.permissions import IsAdminOrSuperuser


class AdminNoteListCreateView(generics.ListCreateAPIView):
    """
    List and create admin notes.

    - GET: Admins/Superusers see all notes; Candidates see only notes about themselves
    - POST: Only Admins/Superusers can create notes
    """
    serializer_class = AdminNoteSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Admins and Superusers can see all notes
        if user.role in ['admin', 'superuser']:
            return AdminNote.objects.all()
        # Candidates can only see notes about themselves
        return AdminNote.objects.filter(candidate=user)

    def perform_create(self, serializer):
        # Only admins and superusers can create notes
        if self.request.user.role not in ['admin', 'superuser']:
            raise PermissionDenied("Only admins can create notes.")
        serializer.save(admin=self.request.user)


class AdminNoteDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete an admin note.

    - Admins/Superusers can access any note
    - Candidates can only view notes about themselves (read-only)
    """
    serializer_class = AdminNoteSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role in ['admin', 'superuser']:
            return AdminNote.objects.all()
        # Candidates can only see notes about themselves
        return AdminNote.objects.filter(candidate=user)

    def check_object_permissions(self, request, obj):
        super().check_object_permissions(request, obj)
        # Candidates cannot modify notes, only view
        if request.user.role == 'candidate' and request.method not in permissions.SAFE_METHODS:
            raise PermissionDenied("Candidates cannot modify admin notes.")


class CandidateNotesView(generics.ListAPIView):
    """
    List all notes for a specific candidate.

    - Only Admins/Superusers can access this endpoint
    """
    serializer_class = AdminNoteSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSuperuser]

    def get_queryset(self):
        candidate_id = self.kwargs['candidate_id']
        return AdminNote.objects.filter(candidate_id=candidate_id)
