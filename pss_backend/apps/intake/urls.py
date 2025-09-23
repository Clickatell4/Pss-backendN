from django.urls import path
from . import views

urlpatterns = [
    path('api/intake/', views.IntakeSubmissionView.as_view(), name='intake_submission'),
    path('api/intake/<int:user_id>/', views.IntakeDetailView.as_view(), name='intake_detail'),
]
