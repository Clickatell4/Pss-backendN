from django.urls import path
from . import views

urlpatterns = [
    path('', views.IntakeSubmissionView.as_view(), name='intake_submission'),
    path('<int:user_id>/', views.IntakeDetailView.as_view(), name='intake_detail'),
]
