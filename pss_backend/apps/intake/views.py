from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from apps.users.models import UserProfile
from apps.users.serializers import UserProfileSerializer
from rest_framework import status

class IntakeSubmissionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        intake_data = request.data.get('intake_data', {})
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        for field, value in intake_data.items():
            if hasattr(profile, field):
                setattr(profile, field, value)
        profile.save()
        request.user.has_completed_intake = True
        request.user.save()
        return Response({'detail': 'Intake saved'}, status=status.HTTP_200_OK)

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
