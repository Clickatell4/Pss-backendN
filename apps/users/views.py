from rest_framework import generics, permissions
from .models import User, UserProfile
from .serializers import UserSerializer, UserProfileSerializer
from .permissions import IsAdminOrSelf

class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSelf]

class UserProfileView(generics.RetrieveUpdateAPIView):
    queryset = UserProfile.objects.select_related('user').all()
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSelf]

class CandidateListView(generics.ListAPIView):
    queryset = User.objects.filter(role='candidate')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
