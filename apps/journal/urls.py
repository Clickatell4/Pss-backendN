from django.urls import path
from . import views

urlpatterns = [
    path('', views.JournalEntryListCreateView.as_view(), name='journal_list_create'),
    path('<int:pk>/', views.JournalEntryDetailView.as_view(), name='journal_detail'),
    path('stats/', views.JournalStatsView.as_view(), name='journal_stats'),
]
