from django.contrib import admin
from .models import AdminNote

@admin.register(AdminNote)
class AdminNoteAdmin(admin.ModelAdmin):
    list_display = ('title', 'candidate', 'admin', 'created_at', 'is_important')
    search_fields = ('title', 'candidate__email', 'admin__email')
    list_filter = ('category', 'is_important')
