from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
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


class CreateAdminView(APIView):
    """
    Superusers can create admin users.
    Only accessible to users with role='superuser'.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Check if user is superuser
        if request.user.role != 'superuser':
            return Response(
                {'error': 'Only superusers can create admin accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get data from request
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        # Validation
        if not email or not password:
            return Response(
                {'error': 'Email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response(
                {'error': 'User with this email already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Create admin user
            admin_user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role='admin',
                is_staff=True  # Give staff access to admin dashboard
            )

            return Response(
                {
                    'message': 'Admin user created successfully',
                    'user': {
                        'id': admin_user.id,
                        'email': admin_user.email,
                        'first_name': admin_user.first_name,
                        'last_name': admin_user.last_name,
                        'role': admin_user.role
                    }
                },
                status=status.HTTP_201_CREATED
            )
        except Exception:
            return Response(
                {'error': 'Failed to create admin user'},
                status=status.HTTP_400_BAD_REQUEST
            )


class CreateCandidateView(APIView):
    """
    Admins can create candidate users.
    Only accessible to users with role='admin'.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Check if user is admin
        if request.user.role != 'admin':
            return Response(
                {'error': 'Only admins can create candidate accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get data from request
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        # Validation
        if not email or not password:
            return Response(
                {'error': 'Email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response(
                {'error': 'User with this email already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Create candidate user
            candidate_user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role='candidate'
            )

            return Response(
                {
                    'message': 'Candidate user created successfully',
                    'user': {
                        'id': candidate_user.id,
                        'email': candidate_user.email,
                        'first_name': candidate_user.first_name,
                        'last_name': candidate_user.last_name,
                        'role': candidate_user.role
                    }
                },
                status=status.HTTP_201_CREATED
            )
        except Exception:
            return Response(
                {'error': 'Failed to create candidate user'},
                status=status.HTTP_400_BAD_REQUEST
            )
