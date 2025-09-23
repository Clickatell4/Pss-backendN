from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import LoginView
urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    # path('logout/', LogoutView.as_view(), name='logout'),  # Removed since not implemented
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # path('me/', CurrentUserView.as_view(), name='current_user'),
]