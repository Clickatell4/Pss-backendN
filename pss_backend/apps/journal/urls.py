from django.urls import path
from . import views

urlpatterns = [
    path('api/journal/', views.JournalEntryListCreateView.as_view(), name='journal_list_create'),
    path('api/journal/<int:pk>/', views.JournalEntryDetailView.as_view(), name='journal_detail'),
    path('api/journal/stats/', views.JournalStatsView.as_view(), name='journal_stats'),
]
