from django.urls import path
from . import views

urlpatterns = [
    path('admin-stats/', views.AdminDashboardStatsView.as_view(), name='admin_dashboard_stats'),
    path('candidate-stats/', views.CandidateDashboardView.as_view(), name='candidate_dashboard'),
]