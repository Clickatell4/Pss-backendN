from django.urls import path
from . import views

urlpatterns = [
    path('api/admin-notes/', views.AdminNoteListCreateView.as_view(), name='admin_note_list_create'),
    path('api/admin-notes/<int:pk>/', views.AdminNoteDetailView.as_view(), name='admin_note_detail'),
    path('api/admin-notes/candidate/<int:candidate_id>/', views.CandidateNotesView.as_view(), name='candidate_notes'),
]
