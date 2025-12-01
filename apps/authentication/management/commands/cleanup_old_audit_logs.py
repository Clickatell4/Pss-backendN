"""
SCRUM-8: Management command to cleanup old audit logs
POPIA Compliance: Retain logs for minimum 2 years, then cleanup

Usage:
    python manage.py cleanup_old_audit_logs --retention-years=2
    python manage.py cleanup_old_audit_logs --dry-run  # Test without deleting
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from auditlog.models import LogEntry


class Command(BaseCommand):
    help = 'Delete audit logs older than specified retention period (default: 2 years for POPIA compliance)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--retention-years',
            type=int,
            default=2,
            help='Number of years to retain audit logs (default: 2 for POPIA compliance)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )

    def handle(self, *args, **options):
        retention_years = options['retention_years']
        dry_run = options['dry_run']

        # Calculate cutoff date
        cutoff_date = timezone.now() - timedelta(days=365 * retention_years)

        # Find old logs
        old_logs = LogEntry.objects.filter(timestamp__lt=cutoff_date)
        log_count = old_logs.count()

        if log_count == 0:
            self.stdout.write(
                self.style.SUCCESS(
                    f'No audit logs older than {retention_years} years found.'
                )
            )
            return

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f'DRY RUN: Would delete {log_count} audit log entries older than {cutoff_date.date()}'
                )
            )
            # Show sample of what would be deleted
            sample_logs = old_logs[:10]
            self.stdout.write('\nSample of logs that would be deleted:')
            for log in sample_logs:
                self.stdout.write(
                    f'  - {log.timestamp.date()} | {log.actor} | {log.action} | {log.content_type}'
                )
            if log_count > 10:
                self.stdout.write(f'\n  ... and {log_count - 10} more')
        else:
            # Confirm deletion
            self.stdout.write(
                self.style.WARNING(
                    f'About to delete {log_count} audit log entries older than {cutoff_date.date()}'
                )
            )

            confirm = input('Are you sure you want to proceed? (yes/no): ')
            if confirm.lower() != 'yes':
                self.stdout.write(self.style.ERROR('Deletion cancelled.'))
                return

            # Delete old logs
            deleted_count, _ = old_logs.delete()

            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully deleted {deleted_count} audit log entries older than {retention_years} years'
                )
            )

        # Show statistics
        remaining_logs = LogEntry.objects.count()
        self.stdout.write(
            self.style.SUCCESS(
                f'\nRemaining audit logs: {remaining_logs}'
            )
        )
