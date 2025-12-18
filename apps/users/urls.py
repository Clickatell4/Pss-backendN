from django.urls import path
from .views import (
    UserListCreateView,
    UserDetailView,
    UserProfileView,
    CandidateListView,
    CreateAdminView,
    CreateCandidateView,
)

# Admin-only actions (SCRUM-39)
from .views_admin import (
    activate_user,
    deactivate_user,
)

urlpatterns = [
    # User CRUD
    path("", UserListCreateView.as_view(), name="user_list_create"),
    path("<int:pk>/", UserDetailView.as_view(), name="user_detail"),
    path("<int:pk>/profile/", UserProfileView.as_view(), name="user_profile"),

    # User creation helpers
    path("candidates/", CandidateListView.as_view(), name="candidate_list"),
    path("create-admin/", CreateAdminView.as_view(), name="create_admin"),
    path("create-candidate/", CreateCandidateView.as_view(), name="create_candidate"),

    # 🔐 Admin management actions (SCRUM-39)
    path("<int:user_id>/activate/", activate_user, name="activate_user"),
    path("<int:user_id>/deactivate/", deactivate_user, name="deactivate_user"),
]
