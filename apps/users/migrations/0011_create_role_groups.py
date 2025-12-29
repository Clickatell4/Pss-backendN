from django.db import migrations


def create_groups_and_permissions(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")

    groups = {
        "Super Admin": Permission.objects.all(),
        "Admin": Permission.objects.filter(
            codename__in=[
                "view_user",
                "change_user",
                "view_userprofile",
                "change_userprofile",
            ]
        ),
        "Counselor": Permission.objects.filter(
            codename__in=[
                "view_userprofile",
                "add_journalentry",
                "view_journalentry",
            ]
        ),
        "Read Only Admin": Permission.objects.filter(
            codename__startswith="view_"
        ),
    }

    for group_name, perms in groups.items():
        group, _ = Group.objects.get_or_create(name=group_name)
        group.permissions.set(perms)


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0010_remove_accountdeletionschedule_users_accou_schedul_0f1f41_idx_and_more"),
        ("auth", "__latest__"),
    ]

    operations = [
        migrations.RunPython(create_groups_and_permissions),
    ]
