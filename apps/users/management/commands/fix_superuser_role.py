from django.core.management.base import BaseCommand
from apps.users.models import User


class Command(BaseCommand):
    help = 'Updates all Django superusers to have role="superuser"'

    def handle(self, *args, **options):
        # Find all users with is_superuser=True but role != 'superuser'
        superusers = User.objects.filter(is_superuser=True).exclude(role='superuser')

        count = 0
        for user in superusers:
            old_role = user.role
            user.role = 'superuser'
            user.save()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Updated {user.email}: {old_role} → superuser'
                )
            )
            count += 1

        if count == 0:
            self.stdout.write(
                self.style.WARNING('No superusers needed updating')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(f'Successfully updated {count} superuser(s)')
            )