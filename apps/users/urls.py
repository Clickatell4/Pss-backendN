from django.urls import path
from .views import (
    UserListCreateView,
    UserDetailView,
    UserProfileView,
    CandidateListView,
    CreateAdminView,
    CreateCandidateView
)

urlpatterns = [
    path('', UserListCreateView.as_view(), name='user_list_create'),
    path('<int:pk>/', UserDetailView.as_view(), name='user_detail'),
    path('<int:pk>/profile/', UserProfileView.as_view(), name='user_profile'),
    path('candidates/', CandidateListView.as_view(), name='candidate_list'),
    path('create-admin/', CreateAdminView.as_view(), name='create_admin'),
    path('create-candidate/', CreateCandidateView.as_view(), name='create_candidate'),
]