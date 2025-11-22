# Generated manually for SCRUM-6: Encrypt existing PII data
"""
Data migration to encrypt existing plaintext PII data.

This migration handles the encryption of existing data that was stored
in plaintext before the encrypted fields were implemented.

IMPORTANT: This migration should only be run ONCE. Running it multiple
times on already-encrypted data will corrupt the data.
"""

from django.db import migrations


def encrypt_existing_data(apps, schema_editor):
    """
    Encrypt existing plaintext PII data.

    The EncryptedField types automatically encrypt on save,
    so we just need to re-save each record to trigger encryption.
    """
    UserProfile = apps.get_model('users', 'UserProfile')

    # Get all profiles with any PII data
    profiles = UserProfile.objects.all()

    for profile in profiles:
        # Simply saving the record will trigger encryption
        # because the encrypted fields encrypt on save
        profile.save()

    print(f"Encrypted PII data for {profiles.count()} user profiles.")


def reverse_encrypt(apps, schema_editor):
    """
    Reverse migration is not possible - data cannot be unencrypted
    without running a separate decryption migration.
    """
    # Cannot reverse encryption automatically
    # Data would need to be manually decrypted if needed
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_encrypt_pii_fields'),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_data, reverse_encrypt),
    ]
