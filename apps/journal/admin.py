from django.contrib import admin
from .models import JournalEntry

@admin.register(JournalEntry)
class JournalAdmin(admin.ModelAdmin):
    list_display = ('user', 'date', 'mood', 'energy_level')
    search_fields = ('user__email', 'activities')
    list_filter = ('mood', 'date')
