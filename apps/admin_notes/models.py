from django.db import models
from apps.users.models import User
from auditlog.registry import auditlog

class AdminNote(models.Model):
    CATEGORY_CHOICES = [
        ('progress', 'Progress Update'),
        ('concern', 'Concern'),
        ('achievement', 'Achievement'),
        ('medical', 'Medical'),
        ('accommodation', 'Accommodation'),
        ('general', 'General'),
    ]
    candidate = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_notes')
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_notes')
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    title = models.CharField(max_length=200)
    content = models.TextField()
    is_important = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.candidate.email})"


# SCRUM-8: Register AdminNote for audit logging
# Tracks who creates/modifies admin notes about candidates
auditlog.register(AdminNote)
