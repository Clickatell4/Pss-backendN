from rest_framework import generics, permissions
from .models import AdminNote
from .serializers import AdminNoteSerializer
from apps.users.permissions import IsAdminOrSelf

class AdminNoteListCreateView(generics.ListCreateAPIView):
    queryset = AdminNote.objects.all()
    serializer_class = AdminNoteSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(admin=self.request.user)

class AdminNoteDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = AdminNote.objects.all()
    serializer_class = AdminNoteSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSelf]

class CandidateNotesView(generics.ListAPIView):
    serializer_class = AdminNoteSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        candidate_id = self.kwargs['candidate_id']
        user = self.request.user
        if user.role == 'admin':
            return AdminNote.objects.filter(candidate_id=candidate_id)
        return AdminNote.objects.filter(candidate=user)
