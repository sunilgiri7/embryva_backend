from rest_framework import serializers

from apis.backends import User
from .models import APIKey

class APIKeyCreateSerializer(serializers.Serializer):
    email = serializers.EmailField(
        required=True,
        help_text="The email address of the clinic for which to generate the key."
    )

class APIKeySerializer(serializers.ModelSerializer):
    hospital_email = serializers.EmailField(read_only=True)

    class Meta:
        model = APIKey
        fields = ['id', 'hospital_email', 'key', 'is_active', 'created_at']
        read_only_fields = ['id', 'clinic', 'hospital_email', 'key', 'is_active', 'created_at']
        depth = 1

class ExternalMatchSerializer(serializers.Serializer):
    donor_type_preference = serializers.CharField()
    location = serializers.CharField()
    preferred_height_min = serializers.IntegerField(required=False)
    preferred_height_max = serializers.IntegerField(required=False)
    preferred_ethnicity = serializers.CharField(required=False)
    preferred_eye_color = serializers.CharField(required=False)
    preferred_hair_color = serializers.CharField(required=False)
    preferred_education_level = serializers.CharField(required=False)
    genetic_screening_required = serializers.BooleanField(required=False)
    preferred_age_min = serializers.IntegerField(required=False)
    preferred_age_max = serializers.IntegerField(required=False)
    preferred_occupation = serializers.CharField(required=False)
    preferred_religion = serializers.CharField(required=False)
    importance_physical = serializers.IntegerField(required=False)
    importance_education = serializers.IntegerField(required=False)
    importance_medical = serializers.IntegerField(required=False)
    importance_personality = serializers.IntegerField(required=False)
    special_requirements = serializers.CharField(required=False)

class APIKeyToggleSerializer(serializers.ModelSerializer):
    """
    Serializer for toggling the 'is_active' status of an APIKey.
    """
    class Meta:
        model = APIKey
        fields = ['is_active']