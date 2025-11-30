from django.contrib.auth import authenticate, get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from apps.users.serializers import UserSerializer
from apps.users.permissions import IsSuperuser, IsAdminOrSuperuser
from pss_backend.throttles import AuthRateThrottle, RegisterRateThrottle

User = get_user_model()

class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthRateThrottle]  # SCRUM-10: Rate limit login attempts

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({
                'detail': 'Email and password are required',
                'errors': {
                    'email': ['This field is required.'] if not email else [],
                    'password': ['This field is required.'] if not password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        if '@' not in email:
            return Response({
                'detail': 'Invalid email format',
                'errors': {'email': ['Enter a valid email address.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate CAPACITI email domain
        if not email.endswith('@capaciti.org.za'):
            return Response({
                'detail': 'Only CAPACITI email addresses are allowed',
                'errors': {'email': ['Email must be a CAPACITI email address']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = authenticate(request, username=email, password=password)

            if user is not None:
                if not user.is_active:
                    return Response({
                        'detail': 'Account is deactivated'
                    }, status=status.HTTP_401_UNAUTHORIZED)

                refresh = RefreshToken.for_user(user)
                user_data = UserSerializer(user).data
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': user_data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'detail': 'Invalid email or password'
                }, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({
                'detail': 'Authentication error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            return Response({'detail': 'Successfully logged out'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [RegisterRateThrottle]  # SCRUM-10: Rate limit registration attempts

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        # Security: Public registration only creates 'candidate' role accounts
        # Admin/superuser accounts must be created through protected endpoints
        role = 'candidate'

        # Validation
        if not email or not password:
            return Response({
                'error': 'Email and password are required',
                'errors': {
                    'email': ['This field is required.'] if not email else [],
                    'password': ['This field is required.'] if not password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        if '@' not in email:
            return Response({
                'error': 'Invalid email format',
                'errors': {'email': ['Enter a valid email address.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate CAPACITI email domain
        if not email.endswith('@capaciti.org.za'):
            return Response({
                'error': 'Only CAPACITI email addresses are allowed',
                'errors': {'email': ['Email must be a CAPACITI email address (@capaciti.org.za)']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response({
                'error': 'User with this email already exists',
                'errors': {'email': ['A user with this email already exists.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create user with 'candidate' role only
            user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role=role
            )

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            user_data = UserSerializer(user).data

            return Response({
                'user': user_data,
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }, status=status.HTTP_201_CREATED)

        except Exception:
            return Response({
                'error': 'Failed to create user'
            }, status=status.HTTP_400_BAD_REQUEST)


class CreateAdminView(APIView):
    """
    Protected endpoint for creating admin accounts.
    Only superusers can create admin accounts.
    """
    permission_classes = [IsSuperuser]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        # Validation
        if not email or not password:
            return Response({
                'error': 'Email and password are required',
                'errors': {
                    'email': ['This field is required.'] if not email else [],
                    'password': ['This field is required.'] if not password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        if '@' not in email:
            return Response({
                'error': 'Invalid email format',
                'errors': {'email': ['Enter a valid email address.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate CAPACITI email domain
        if not email.endswith('@capaciti.org.za'):
            return Response({
                'error': 'Only CAPACITI email addresses are allowed',
                'errors': {'email': ['Email must be a CAPACITI email address (@capaciti.org.za)']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response({
                'error': 'User with this email already exists',
                'errors': {'email': ['A user with this email already exists.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create admin user
            user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role='admin'
            )

            user_data = UserSerializer(user).data

            return Response({
                'message': 'Admin user created successfully',
                'user': user_data
            }, status=status.HTTP_201_CREATED)

        except Exception:
            return Response({
                'error': 'Failed to create admin user'
            }, status=status.HTTP_400_BAD_REQUEST)


class CreateSuperuserView(APIView):
    """
    Protected endpoint for creating superuser accounts.
    Only existing superusers can create new superuser accounts.
    """
    permission_classes = [IsSuperuser]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        # Validation
        if not email or not password:
            return Response({
                'error': 'Email and password are required',
                'errors': {
                    'email': ['This field is required.'] if not email else [],
                    'password': ['This field is required.'] if not password else []
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        if '@' not in email:
            return Response({
                'error': 'Invalid email format',
                'errors': {'email': ['Enter a valid email address.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate CAPACITI email domain
        if not email.endswith('@capaciti.org.za'):
            return Response({
                'error': 'Only CAPACITI email addresses are allowed',
                'errors': {'email': ['Email must be a CAPACITI email address (@capaciti.org.za)']}
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response({
                'error': 'User with this email already exists',
                'errors': {'email': ['A user with this email already exists.']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create superuser
            user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role='superuser'
            )

            user_data = UserSerializer(user).data

            return Response({
                'message': 'Superuser created successfully',
                'user': user_data
            }, status=status.HTTP_201_CREATED)

        except Exception:
            return Response({
                'error': 'Failed to create superuser'
            }, status=status.HTTP_400_BAD_REQUEST)