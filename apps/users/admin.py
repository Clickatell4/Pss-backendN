from django.contrib import admin
from .models import User, UserProfile

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'first_name', 'last_name', 'role', 'has_completed_intake', 'date_joined', 'is_staff']
    list_filter = ['role', 'has_completed_intake', 'date_joined', 'is_staff']
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ('email',)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'diagnosis', 'created_at']
    search_fields = ['user__email', 'diagnosis']
