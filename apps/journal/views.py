from rest_framework import generics, permissions
from rest_framework.response import Response
from django.db.models import Avg, Sum
from django.utils import timezone
from datetime import timedelta

from .models import JournalEntry
from .serializers import JournalEntrySerializer
from apps.users.permissions import IsAdminOrSelf


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
    """
    SCRUM-45: SQL Injection Prevention
    - All queries use Django ORM (parameterized)
    - No raw SQL or string interpolation
    - User input never directly in queries
    """
    permission_classes = [permissions.IsAuthenticated]

    # Prevent ANY user-controlled value ever being used in date calculations
    SAFE_RECENT_DAYS = 7

    def get(self, request):
        user = request.user

        # Admins see all entries; normal users only see their own
        if user.role == 'admin':
            qs = JournalEntry.objects.all()
        else:
            qs = JournalEntry.objects.filter(user=user)

        # --- Safe: ORM handles all SQL, no user input in calculations ---
        total_entries = qs.count()

        last_entry = qs.order_by('-date').first()
        last_entry_date = last_entry.date if last_entry else None

        # SAFE: timedelta is static, not built from user input
        seven_days_ago = timezone.now().date() - timedelta(days=self.SAFE_RECENT_DAYS)

        recent_barriers = (
            qs.filter(date__gte=seven_days_ago)
              .aggregate(total=Sum('barrier_count'))
              .get('total') or 0
        )

        avg_energy = qs.aggregate(avg=Avg('energy_level')).get('avg') or 0

        return Response({
            "total_entries": total_entries,
            "last_entry_date": last_entry_date,
            "recent_barriers": recent_barriers,
            "avg_energy_level": float(avg_energy),
        })
