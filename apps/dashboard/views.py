from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.utils import timezone
from datetime import timedelta
from django.db import models

from apps.users.models import User
from apps.journal.models import JournalEntry
from apps.admin_notes.models import AdminNote


class AdminDashboardStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':
            return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        # Calculate admin dashboard statistics
        stats = self.get_admin_stats()
        return Response(stats, status=status.HTTP_200_OK)

    def get_admin_stats(self):
        """Calculate stats for admin dashboard"""
        total_candidates = User.objects.filter(role='candidate').count()
        active_candidates = User.objects.filter(
            role='candidate',
            has_completed_intake=True
        ).count()
        pending_intake = User.objects.filter(
            role='candidate',
            has_completed_intake=False
        ).count()

        # Recent barriers (last 7 days)
        week_ago = timezone.now() - timedelta(days=7)
        recent_barriers = JournalEntry.objects.filter(
            date__gte=week_ago.date()
        ).aggregate(total=models.Sum('barrier_count'))['total'] or 0

        # Recent journal entries count
        recent_entries = JournalEntry.objects.filter(
            created_at__gte=week_ago
        ).count()

        # Admin notes count
        total_admin_notes = AdminNote.objects.count()
        recent_admin_notes = AdminNote.objects.filter(
            created_at__gte=week_ago
        ).count()

        return {
            'total_candidates': total_candidates,
            'active_candidates': active_candidates,
            'pending_intake': pending_intake,
            'recent_barriers': recent_barriers,
            'recent_entries': recent_entries,
            'total_admin_notes': total_admin_notes,
            'recent_admin_notes': recent_admin_notes
        }


class CandidateDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'candidate':
            return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        # Get candidate-specific dashboard data
        stats = self.get_candidate_stats(request.user)
        return Response(stats, status=status.HTTP_200_OK)

    def get_candidate_stats(self, user):
        """Calculate stats for candidate dashboard"""
        # Journal stats
        total_entries = JournalEntry.objects.filter(user=user).count()

        if total_entries > 0:
            # Last entry date
            last_entry = JournalEntry.objects.filter(user=user).first()
            last_entry_date = last_entry.date if last_entry else None

            # Average energy level
            avg_energy = JournalEntry.objects.filter(user=user).aggregate(
                avg=models.Avg('energy_level')
            )['avg'] or 0

            # Recent barriers (last 30 days)
            month_ago = timezone.now() - timedelta(days=30)
            recent_barriers = JournalEntry.objects.filter(
                user=user,
                date__gte=month_ago.date()
            ).aggregate(total=models.Sum('barrier_count'))['total'] or 0

            # Mood distribution
            mood_stats = JournalEntry.objects.filter(user=user).values('mood').annotate(
                count=models.Count('mood')
            )
        else:
            last_entry_date = None
            avg_energy = 0
            recent_barriers = 0
            mood_stats = []

        # Admin notes about this candidate
        admin_notes_count = AdminNote.objects.filter(candidate=user).count()

        return {
            'total_entries': total_entries,
            'last_entry_date': last_entry_date,
            'avg_energy_level': round(avg_energy, 1) if avg_energy else 0,
            'recent_barriers': recent_barriers,
            'admin_notes_count': admin_notes_count,
            'mood_distribution': list(mood_stats),
            'has_completed_intake': user.has_completed_intake
        }