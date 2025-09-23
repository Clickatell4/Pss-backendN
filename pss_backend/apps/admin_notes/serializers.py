from rest_framework import serializers
from .models import AdminNote

class AdminNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminNote
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at', 'admin')
