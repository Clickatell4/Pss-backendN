from rest_framework import generics, permissions
from .models import JournalEntry
from .serializers import JournalEntrySerializer
from apps.users.permissions import IsAdminOrSelf
from rest_framework.response import Response
from django.db.models import Avg, Sum
from django.utils import timezone

class JournalEntryListCreateView(generics.ListCreateAPIView):
    serializer_class = JournalEntrySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return JournalEntry.objects.all()
        return JournalEntry.objects.filter(user=user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class JournalEntryDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = JournalEntry.objects.all()
    serializer_class = JournalEntrySerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSelf]

class JournalStatsView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        qs = JournalEntry.objects.filter(user=user) if user.role != 'admin' else JournalEntry.objects.all()
        total_entries = qs.count()
        last_entry = qs.order_by('-date').first()
        last_entry_date = last_entry.date if last_entry else None
        recent_barriers = qs.filter(date__gte=timezone.now().date()-timezone.timedelta(days=7)).aggregate(total=Sum('barrier_count'))['total'] or 0
        avg_energy = qs.aggregate(avg=Avg('energy_level'))['avg'] or 0
        return Response({
            'total_entries': total_entries,
            'last_entry_date': last_entry_date,
            'recent_barriers': recent_barriers,
            'avg_energy_level': float(avg_energy),
        })
