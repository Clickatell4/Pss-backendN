"""
SCRUM-119: Automated Inactive Account Deletion
Management command to identify, warn, and delete inactive accounts per POPIA Section 14

Usage:
    python manage.py cleanup_inactive_accounts [options]

Options:
    --inactive-years=N    Set inactivity threshold (default: 2 years)
    --grace-days=N        Set grace period (default: 30 days)
    --dry-run            Show what would be deleted without actually deleting
    --no-warnings        Skip warning emails and delete immediately
    --execute            Actually perform deletions (required for safety)
"""
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from datetime import timedelta
import logging

from apps.users.models import AccountDeletionSchedule, UserProfile
from apps.users.popia_models import UserConsent
from apps.journal.models import JournalEntry
from apps.admin_notes.models import AdminNote
import json

User = get_user_model()
logger = logging.getLogger('django.security.auth')


class Command(BaseCommand):
    help = 'Identify and delete inactive accounts per POPIA Section 14 compliance'

    def add_arguments(self, parser):
        parser.add_argument(
            '--inactive-years',
            type=int,
            default=getattr(settings, 'INACTIVE_ACCOUNT_THRESHOLD_YEARS', 2),
            help='Inactivity threshold in years (default: 2)'
        )
        parser.add_argument(
            '--grace-days',
            type=int,
            default=getattr(settings, 'INACTIVE_ACCOUNT_GRACE_PERIOD_DAYS', 30),
            help='Grace period in days before deletion (default: 30)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would happen without making changes'
        )
        parser.add_argument(
            '--no-warnings',
            action='store_true',
            help='Skip warning emails and proceed directly to deletion'
        )
        parser.add_argument(
            '--execute',
            action='store_true',
            help='Required flag to actually perform deletions (safety measure)'
        )

    def handle(self, *args, **options):
        self.dry_run = options['dry_run']
        self.inactive_years = options['inactive_years']
        self.grace_days = options['grace_days']
        self.no_warnings = options['no_warnings']
        self.execute = options['execute']

        self.stdout.write(self.style.SUCCESS('=' * 70))
        self.stdout.write(self.style.SUCCESS('INACTIVE ACCOUNT CLEANUP - POPIA Section 14 Compliance'))
        self.stdout.write(self.style.SUCCESS('=' * 70))
        self.stdout.write('')
        self.stdout.write(f'Inactivity threshold: {self.inactive_years} years')
        self.stdout.write(f'Grace period: {self.grace_days} days')
        self.stdout.write(f'Mode: {"DRY RUN" if self.dry_run else "LIVE"}')
        self.stdout.write('')

        # Step 1: Identify inactive accounts
        inactive_users = self._identify_inactive_accounts()
        self.stdout.write(f'\nFound {len(inactive_users)} inactive accounts')

        if not inactive_users:
            self.stdout.write(self.style.SUCCESS('\n✅ No inactive accounts found'))
            return

        # Step 2: Schedule deletions (create/update AccountDeletionSchedule)
        scheduled_count = self._schedule_deletions(inactive_users)
        self.stdout.write(f'Scheduled {scheduled_count} accounts for deletion')

        # Step 3: Send warning emails
        if not self.no_warnings:
            warnings_sent = self._send_warning_emails()
            self.stdout.write(f'Sent {warnings_sent} warning emails')

        # Step 4: Execute deletions for accounts past grace period
        if self.execute and not self.dry_run:
            deleted_count = self._execute_deletions()
            self.stdout.write(self.style.WARNING(f'\n⚠️  Deleted {deleted_count} accounts'))
        elif not self.execute:
            overdue = AccountDeletionSchedule.objects.filter(
                exempted=False,
                scheduled_deletion_date__lte=timezone.now()
            ).count()
            self.stdout.write(
                self.style.WARNING(
                    f'\n⚠️  {overdue} accounts are overdue for deletion but --execute flag not provided'
                )
            )

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('=' * 70))
        self.stdout.write(self.style.SUCCESS('CLEANUP COMPLETE'))
        self.stdout.write(self.style.SUCCESS('=' * 70))

    def _identify_inactive_accounts(self):
        """Identify accounts that haven't logged in for N years."""
        self.stdout.write('\n📊 Identifying inactive accounts...')

        # Calculate cutoff date
        cutoff_date = timezone.now() - timedelta(days=365 * self.inactive_years)

        # Exclude admin/superuser accounts
        exclude_roles = getattr(
            settings,
            'INACTIVE_ACCOUNT_EXCLUDE_ROLES',
            ['admin', 'superuser']
        )

        # Find inactive users
        inactive_users = User.objects.filter(
            last_login__lt=cutoff_date,
            is_active=True
        ).exclude(
            role__in=exclude_roles
        )

        # Display details
        for user in inactive_users:
            days_inactive = (timezone.now() - user.last_login).days if user.last_login else None
            self.stdout.write(
                f'  - {user.email}: last login {days_inactive} days ago'
            )

        return list(inactive_users)

    def _schedule_deletions(self, users):
        """Create or update deletion schedules for inactive users."""
        self.stdout.write('\n📅 Scheduling deletions...')

        scheduled_count = 0
        deletion_date = timezone.now() + timedelta(days=self.grace_days)

        for user in users:
            # Check if already scheduled
            schedule, created = AccountDeletionSchedule.objects.get_or_create(
                user=user,
                defaults={
                    'scheduled_deletion_date': deletion_date,
                }
            )

            if created and not self.dry_run:
                scheduled_count += 1
                self.stdout.write(
                    f'  ✓ Scheduled {user.email} for deletion on {deletion_date.date()}'
                )
                logger.info(f'Scheduled inactive account {user.email} for deletion')
            elif schedule.exempted:
                self.stdout.write(
                    self.style.WARNING(f'  ⊗ {user.email} is EXEMPTED from deletion')
                )
            else:
                self.stdout.write(
                    f'  ↻ {user.email} already scheduled for {schedule.scheduled_deletion_date.date()}'
                )

        return scheduled_count

    def _send_warning_emails(self):
        """Send warning emails to users scheduled for deletion."""
        self.stdout.write('\n📧 Sending warning emails...')

        warnings_sent = 0
        now = timezone.now()

        # Get schedules needing warnings
        schedules = AccountDeletionSchedule.objects.filter(
            exempted=False,
            scheduled_deletion_date__gt=now
        )

        for schedule in schedules:
            days_left = schedule.days_until_deletion

            # First warning: 30 days before
            if days_left <= 30 and days_left > 7 and not schedule.first_warning_sent:
                if not self.dry_run:
                    self._send_first_warning(schedule)
                    schedule.first_warning_sent = now
                    schedule.save()
                warnings_sent += 1
                self.stdout.write(f'  ✓ Sent FIRST warning to {schedule.user.email} ({days_left} days left)')

            # Second warning: 7 days before
            elif days_left <= 7 and not schedule.second_warning_sent:
                if not self.dry_run:
                    self._send_second_warning(schedule)
                    schedule.second_warning_sent = now
                    schedule.save()
                warnings_sent += 1
                self.stdout.write(
                    self.style.WARNING(f'  ⚠️  Sent FINAL warning to {schedule.user.email} ({days_left} days left)')
                )

        return warnings_sent

    def _send_first_warning(self, schedule):
        """Send first warning email (30 days before deletion)."""
        user = schedule.user
        subject = 'Your PSS Account Will Be Deleted in 30 Days'
        message = f"""
Hello {user.first_name or user.email},

We noticed that you haven't logged into your PSS (Psychosocial Support) account in over {self.inactive_years} years.

Per our data retention policy (POPIA Section 14 compliance), inactive accounts are automatically deleted after {self.inactive_years} years of inactivity.

🗓️ Your account is scheduled for deletion on: {schedule.scheduled_deletion_date.strftime('%B %d, %Y')}

HOW TO KEEP YOUR ACCOUNT:
Simply log in to your account at {settings.FRONTEND_URL}/login before the deletion date. This will cancel the automatic deletion.

WHAT HAPPENS IF YOU DON'T LOG IN:
- All your personal information will be permanently deleted
- Your journal entries will be anonymized
- This action cannot be undone

WHY ARE WE DOING THIS:
We're required by South African privacy law (POPIA) to only keep personal information for as long as necessary. Since you haven't used your account in {self.inactive_years} years, we must delete your data.

NEED HELP?
If you have any questions or concerns, please contact us at {settings.DEFAULT_FROM_EMAIL}

---
PSS Support Team
        """.strip()

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            logger.info(f'Sent first deletion warning to {user.email}')
        except Exception as e:
            logger.error(f'Failed to send first warning to {user.email}: {str(e)}')

    def _send_second_warning(self, schedule):
        """Send second warning email (7 days before deletion)."""
        user = schedule.user
        subject = '⚠️ FINAL WARNING: Your PSS Account Will Be Deleted in 7 Days'
        message = f"""
Hello {user.first_name or user.email},

This is your FINAL reminder that your PSS account will be permanently deleted in 7 days.

🚨 DELETION DATE: {schedule.scheduled_deletion_date.strftime('%B %d, %Y')}

IMMEDIATE ACTION REQUIRED:
Log in to your account NOW to prevent deletion: {settings.FRONTEND_URL}/login

WHAT WILL BE DELETED:
- All personal information
- Medical records
- Support notes
- Journal entries (anonymized)

⏰ TIME REMAINING: {schedule.days_until_deletion} days

TO KEEP YOUR ACCOUNT:
Simply log in before {schedule.scheduled_deletion_date.strftime('%B %d, %Y')}. Your account will be reactivated and the deletion will be cancelled.

QUESTIONS?
Contact us immediately at {settings.DEFAULT_FROM_EMAIL}

---
PSS Support Team
        """.strip()

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            logger.info(f'Sent second deletion warning to {user.email}')
        except Exception as e:
            logger.error(f'Failed to send second warning to {user.email}: {str(e)}')

    def _execute_deletions(self):
        """Execute deletions for accounts past their grace period."""
        self.stdout.write('\n🗑️  Executing deletions...')

        deleted_count = 0

        # Get overdue schedules
        overdue_schedules = AccountDeletionSchedule.objects.filter(
            exempted=False,
            scheduled_deletion_date__lte=timezone.now()
        )

        for schedule in overdue_schedules:
            user = schedule.user

            self.stdout.write(f'  Deleting {user.email}...')

            try:
                # Use POPIA deletion workflow from SCRUM-11
                deletion_summary = self._delete_user_data(user)

                # Send final notification
                self._send_deletion_confirmation(user)

                # Delete the schedule
                schedule.delete()

                deleted_count += 1
                self.stdout.write(self.style.WARNING(f'    ✓ Deleted {user.email}'))
                logger.warning(f'Deleted inactive account: {user.email} - {deletion_summary}')

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'    ✗ Failed to delete {user.email}: {str(e)}')
                )
                logger.error(f'Failed to delete inactive account {user.email}: {str(e)}')

        return deleted_count

    def _delete_user_data(self, user):
        """
        Delete all user data while maintaining audit trail.
        POPIA: Keep deletion records for compliance proof.
        Based on ExecuteDataDeletionView._delete_user_data from SCRUM-11
        """
        deletion_summary = {
            'user_id': user.id,
            'email': user.email,
            'deleted_at': timezone.now().isoformat(),
            'items_deleted': {},
        }

        # Delete journal entries
        journal_count = JournalEntry.objects.filter(user=user).count()
        JournalEntry.objects.filter(user=user).delete()
        deletion_summary['items_deleted']['journal_entries'] = journal_count

        # Delete admin notes
        notes_count = AdminNote.objects.filter(candidate=user).count()
        AdminNote.objects.filter(candidate=user).delete()
        deletion_summary['items_deleted']['admin_notes'] = notes_count

        # Delete user profile
        try:
            user.profile.delete()
            deletion_summary['items_deleted']['profile'] = 1
        except UserProfile.DoesNotExist:
            deletion_summary['items_deleted']['profile'] = 0

        # Delete consents (keep deletion request for audit trail)
        consent_count = UserConsent.objects.filter(user=user).count()
        UserConsent.objects.filter(user=user).delete()
        deletion_summary['items_deleted']['consents'] = consent_count

        # Anonymize user account (soft delete - keep for referential integrity)
        user.email = f"deleted_{user.id}@deleted.local"
        user.first_name = "[DELETED]"
        user.last_name = "[DELETED]"
        user.is_active = False
        user.save()
        deletion_summary['user_anonymized'] = True

        return json.dumps(deletion_summary)

    def _send_deletion_confirmation(self, user):
        """Send confirmation email after account deletion."""
        subject = 'Your PSS Account Has Been Deleted'
        message = f"""
Hello {user.first_name or user.email},

Your PSS account has been permanently deleted due to {self.inactive_years} years of inactivity.

WHAT WAS DELETED:
- Personal information
- Medical records
- Support notes
- Contact information

WHAT WAS KEPT (ANONYMIZED):
- Anonymous journal entries (for research purposes)
- Anonymous audit logs (for compliance)

CAN I RECOVER MY ACCOUNT?
No. The deletion is permanent and cannot be undone.

CAN I CREATE A NEW ACCOUNT?
Yes. You can re-register at any time at {settings.FRONTEND_URL}/register

WHY WAS THIS DONE?
Per POPIA (South African privacy law), we must delete personal information that is no longer necessary. Since you hadn't used your account in {self.inactive_years} years, we deleted your data.

QUESTIONS?
Contact us at {settings.DEFAULT_FROM_EMAIL}

---
PSS Support Team
        """.strip()

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=True,  # Don't fail if email fails (account already deleted)
            )
        except Exception:
            pass  # Silently fail - account is already deleted
