from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import Group

from .models import UserProfile

ROLE_GROUP_MAP = {
    "superuser": "Super Admin",
    "admin": "Admin",
    "counselor": "Counselor",
    "readonly": "Read Only Admin",
}


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def sync_user_role_to_group(sender, instance, **kwargs):
    """
    Ensure user's Django Group matches their role field
    """
    instance.groups.clear()

    group_name = ROLE_GROUP_MAP.get(instance.role)
    if not group_name:
        return

    group = Group.objects.filter(name=group_name).first()
    if group:
        instance.groups.add(group)
