from django.urls import path
from . import views

urlpatterns = [
    path('', views.AdminNoteListCreateView.as_view(), name='admin_note_list_create'),
    path('<int:pk>/', views.AdminNoteDetailView.as_view(), name='admin_note_detail'),
    path('candidate/<int:candidate_id>/', views.CandidateNotesView.as_view(), name='candidate_notes'),
]
