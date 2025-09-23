from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from apps.users.models import UserProfile
from apps.users.serializers import UserProfileSerializer
from rest_framework import status
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

        try:
            profile = complete_intake(request.user, intake_data)
            serializer = UserProfileSerializer(profile)
            return Response({
                'detail': 'Intake completed successfully',
                'profile': serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {'detail': f'Error completing intake: {str(e)}'},
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
