"""
Supabase Storage Backend for Django

Custom Django storage backend that integrates with Supabase Storage.
Used in testing/staging environment for media file uploads.

Features:
- Upload files to Supabase Storage buckets
- Download files from Supabase Storage
- Delete files from storage
- Check file existence
- Get public URLs for files

Configuration (in settings/testing.py):
    DEFAULT_FILE_STORAGE = 'pss_backend.storage_backends.SupabaseMediaStorage'
    SUPABASE_URL = 'https://[PROJECT-REF].supabase.co'
    SUPABASE_KEY = 'your-supabase-anon-or-service-role-key'
    SUPABASE_STORAGE_BUCKET = 'pss-testing-media'
"""
from django.core.files.storage import Storage
from django.core.files.base import ContentFile
from django.conf import settings
from supabase import create_client, Client
import os
import logging

logger = logging.getLogger('django.storage')


class SupabaseMediaStorage(Storage):
    """
    Custom Django storage backend for Supabase Storage.

    Handles all media file operations (upload, download, delete) through
    Supabase's storage API.
    """

    def __init__(self):
        """Initialize Supabase client and bucket configuration."""
        try:
            self.supabase: Client = create_client(
                settings.SUPABASE_URL,
                settings.SUPABASE_KEY
            )
            self.bucket = settings.SUPABASE_STORAGE_BUCKET

            logger.info(
                "SupabaseMediaStorage initialized: bucket=%s, url=%s",
                self.bucket,
                settings.SUPABASE_URL
            )
        except Exception as e:
            logger.error("Failed to initialize SupabaseMediaStorage: %s", str(e))
            raise

    def _save(self, name, content):
        """
        Upload file to Supabase Storage.

        Args:
            name (str): File path/name within the bucket
            content (File): Django file object to upload

        Returns:
            str: The name of the saved file

        Raises:
            Exception: If upload fails
        """
        try:
            # Read file content
            content.seek(0)
            file_data = content.read()

            # Determine content type
            content_type = getattr(content, 'content_type', 'application/octet-stream')

            # Upload to Supabase Storage
            self.supabase.storage.from_(self.bucket).upload(
                name,
                file_data,
                file_options={"content-type": content_type}
            )

            logger.info("File uploaded to Supabase: %s (size: %d bytes)", name, len(file_data))
            return name

        except Exception as e:
            logger.error("Failed to upload file %s to Supabase: %s", name, str(e))
            raise

    def _open(self, name, mode='rb'):
        """
        Download file from Supabase Storage.

        Args:
            name (str): File path/name within the bucket
            mode (str): File open mode (default: 'rb')

        Returns:
            ContentFile: Django file object with file contents

        Raises:
            Exception: If download fails
        """
        try:
            # Download file from Supabase
            response = self.supabase.storage.from_(self.bucket).download(name)

            logger.info("File downloaded from Supabase: %s (size: %d bytes)", name, len(response))
            return ContentFile(response)

        except Exception as e:
            logger.error("Failed to download file %s from Supabase: %s", name, str(e))
            raise

    def exists(self, name):
        """
        Check if file exists in Supabase Storage.

        Args:
            name (str): File path/name within the bucket

        Returns:
            bool: True if file exists, False otherwise
        """
        try:
            # List files in the directory
            directory = os.path.dirname(name)
            filename = os.path.basename(name)

            # If no directory, list from root
            if not directory:
                directory = ''

            files = self.supabase.storage.from_(self.bucket).list(path=directory)

            # Check if filename exists in the list
            exists = any(f['name'] == filename for f in files)

            logger.debug("File existence check for %s: %s", name, exists)
            return exists

        except Exception as e:
            logger.warning("Error checking file existence for %s: %s", name, str(e))
            # If we can't list files, assume it doesn't exist
            return False

    def delete(self, name):
        """
        Delete file from Supabase Storage.

        Args:
            name (str): File path/name within the bucket

        Raises:
            Exception: If deletion fails
        """
        try:
            self.supabase.storage.from_(self.bucket).remove([name])
            logger.info("File deleted from Supabase: %s", name)

        except Exception as e:
            logger.error("Failed to delete file %s from Supabase: %s", name, str(e))
            raise

    def url(self, name):
        """
        Get public URL for file.

        Args:
            name (str): File path/name within the bucket

        Returns:
            str: Public URL to access the file
        """
        # Construct public URL using MEDIA_URL from settings
        url = f"{settings.MEDIA_URL}{name}"
        logger.debug("Generated URL for %s: %s", name, url)
        return url

    def size(self, name):
        """
        Get file size in bytes.

        Args:
            name (str): File path/name within the bucket

        Returns:
            int: File size in bytes, or 0 if not found
        """
        try:
            directory = os.path.dirname(name)
            filename = os.path.basename(name)

            if not directory:
                directory = ''

            files = self.supabase.storage.from_(self.bucket).list(path=directory)

            # Find the file and get its size
            for f in files:
                if f['name'] == filename:
                    size = f.get('metadata', {}).get('size', 0)
                    logger.debug("File size for %s: %d bytes", name, size)
                    return size

            logger.warning("File %s not found when checking size", name)
            return 0

        except Exception as e:
            logger.error("Failed to get size for file %s: %s", name, str(e))
            return 0

    def get_available_name(self, name, max_length=None):
        """
        Get an available name for the file.

        This implementation overwrites existing files with the same name.
        Override this method if you want different behavior (e.g., append numbers).

        Args:
            name (str): Desired file name
            max_length (int): Maximum length for file name

        Returns:
            str: Available file name
        """
        # Simple implementation: just return the name (will overwrite)
        # Override this if you want to avoid overwrites
        return name

    def get_accessed_time(self, name):
        """
        Return the last accessed time (as a datetime) of the file.
        Supabase doesn't track access time, so we raise NotImplementedError.
        """
        raise NotImplementedError("Supabase Storage doesn't provide access time metadata.")

    def get_created_time(self, name):
        """
        Return the creation time (as a datetime) of the file.
        Supabase doesn't provide created time in standard metadata.
        """
        raise NotImplementedError("Supabase Storage doesn't provide creation time metadata.")

    def get_modified_time(self, name):
        """
        Return the last modified time (as a datetime) of the file.
        Supabase doesn't provide modified time in standard metadata.
        """
        raise NotImplementedError("Supabase Storage doesn't provide modified time metadata.")
