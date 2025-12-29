"""
SCRUM-30: Management Command for Session Cleanup
Removes expired user sessions from the database to prevent accumulation
"""
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta
from apps.authentication.models import UserSession


class Command(BaseCommand):
    help = 'Clean up expired user sessions from the database'

    def add_arguments(self, parser):
        """Add command-line arguments."""
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Delete sessions expired more than N days ago (default: 7)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )

    def handle(self, *args, **options):
        """Execute the command."""
        days = options['days']
        dry_run = options['dry_run']

        # Calculate cutoff date
        cutoff_date = timezone.now() - timedelta(days=days)

        # Find expired sessions
        expired_sessions = UserSession.objects.filter(
            expires_at__lt=cutoff_date
        )

        count = expired_sessions.count()

        if count == 0:
            self.stdout.write(
                self.style.SUCCESS(
                    f'No expired sessions found older than {days} days.'
                )
            )
            return

        # Show statistics
        self.stdout.write(
            self.style.WARNING(
                f'\nFound {count} expired session(s) older than {days} days:'
            )
        )
        self.stdout.write(f'  Cutoff date: {cutoff_date.strftime("%Y-%m-%d %H:%M:%S")}')

        # Show sample sessions
        sample_size = min(5, count)
        sample_sessions = expired_sessions[:sample_size]

        self.stdout.write('\nSample sessions to be deleted:')
        for session in sample_sessions:
            self.stdout.write(
                f'  - User: {session.user.email}, '
                f'Device: {session.device_type}, '
                f'Expired: {session.expires_at.strftime("%Y-%m-%d %H:%M")}'
            )

        if count > sample_size:
            self.stdout.write(f'  ... and {count - sample_size} more')

        # Show active session statistics
        active_sessions = UserSession.objects.filter(
            terminated_at__isnull=True,
            expires_at__gt=timezone.now()
        ).count()

        self.stdout.write(
            f'\nActive sessions (will be kept): {active_sessions}'
        )

        # Perform deletion or dry run
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f'\nDRY RUN: Would delete {count} expired session(s). '
                    f'Run without --dry-run to actually delete.'
                )
            )
        else:
            # Delete expired sessions
            deleted_count, _ = expired_sessions.delete()

            self.stdout.write(
                self.style.SUCCESS(
                    f'\nSuccessfully deleted {deleted_count} expired session(s).'
                )
            )

            # Final statistics
            remaining_sessions = UserSession.objects.count()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Remaining sessions in database: {remaining_sessions}'
                )
            )
