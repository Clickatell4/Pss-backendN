from django.urls import path
from .views import UserListCreateView, UserDetailView, UserProfileView, CandidateListView

urlpatterns = [
    path('', UserListCreateView.as_view(), name='user_list_create'),
    path('<int:pk>/', UserDetailView.as_view(), name='user_detail'),
    path('<int:pk>/profile/', UserProfileView.as_view(), name='user_profile'),
    path('candidates/', CandidateListView.as_view(), name='candidate_list'),
]