from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse

def health_check(request):
    return JsonResponse({'status': 'healthy', 'message': 'PSS Backend API is running'})

urlpatterns = [
    path('', health_check, name='health_check'),
    path('api/', health_check, name='api_health_check'),
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.authentication.urls')),
    path('api/users/', include('apps.users.urls')),
    path('api/popia/', include('apps.users.popia_urls')),  # SCRUM-11: POPIA/GDPR compliance endpoints
    path('api/intake/', include('apps.intake.urls')),
    path('api/journal/', include('apps.journal.urls')),
    path('api/admin-notes/', include('apps.admin_notes.urls')),
    path('api/dashboard/', include('apps.dashboard.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)