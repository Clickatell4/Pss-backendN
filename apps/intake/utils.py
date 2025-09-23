from apps.users.models import UserProfile


def complete_intake(user, intake_data):
    """
    Complete intake process for a user
    Updates user profile and marks intake as completed
    """
    # Update user profile
    profile, created = UserProfile.objects.get_or_create(user=user)

    for field, value in intake_data.items():
        if hasattr(profile, field) and value is not None:
            setattr(profile, field, value)

    profile.save()

    # Mark intake as completed
    user.has_completed_intake = True
    user.save()

    return profile