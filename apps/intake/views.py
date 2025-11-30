from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from apps.users.models import UserProfile
from apps.users.serializers import UserProfileSerializer
from rest_framework import status
from django.core.exceptions import ValidationError
from .utils import complete_intake

class IntakeSubmissionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        intake_data = request.data.get('intake_data', {})

        if not intake_data:
            return Response(
                {'detail': 'No intake data provided'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate intake data using UserProfileSerializer
        serializer = UserProfileSerializer(data=intake_data, partial=True)

        try:
            if not serializer.is_valid():
                return Response({
                    'detail': 'Invalid intake data',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            # Complete intake with validated data
            profile = complete_intake(request.user, serializer.validated_data)
            response_serializer = UserProfileSerializer(profile)

            return Response({
                'detail': 'Intake completed successfully',
                'profile': response_serializer.data
            }, status=status.HTTP_200_OK)

        except ValidationError as e:
            return Response({
                'detail': 'Validation error',
                'errors': {'validation': str(e)}
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(
                {'detail': 'Error completing intake. Please try again.'},
                status=status.HTTP_400_BAD_REQUEST
            )

class IntakeDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        if request.user.role != 'admin' and request.user.id != user_id:
            return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        profile = UserProfile.objects.filter(user_id=user_id).first()
        if not profile:
            return Response({'detail': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)
