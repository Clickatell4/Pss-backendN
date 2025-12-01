from django.db import models
from apps.users.models import User
from auditlog.registry import auditlog

class JournalEntry(models.Model):
    ENERGY_CHOICES = [(i, i) for i in range(1, 11)]
    MOOD_CHOICES = [
        ('excellent', 'Excellent'),
        ('good', 'Good'),
        ('okay', 'Okay'),
        ('difficult', 'Difficult'),
        ('very_difficult', 'Very Difficult'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='journal_entries')
    date = models.DateField()
    mood = models.CharField(max_length=20, choices=MOOD_CHOICES)
    energy_level = models.IntegerField(choices=ENERGY_CHOICES)
    activities = models.TextField()
    challenges = models.TextField(blank=True)
    achievements = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    barriers_faced = models.TextField(blank=True)
    barrier_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['user', 'date']
        ordering = ['-date']

    def __str__(self):
        return f"{self.user.email} - {self.date}"


# SCRUM-8: Register JournalEntry for audit logging
# Tracks all journal modifications for security monitoring
auditlog.register(JournalEntry)
