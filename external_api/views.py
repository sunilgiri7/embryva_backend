import secrets
from rest_framework import generics, status
from rest_framework.permissions import IsAdminUser
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.response import Response
from apis.backends import User
from apis.serializers import DonorImportSerializer
from external_api.models import APIKey
from .serializers import APIKeyCreateSerializer, APIKeySerializer, APIKeyToggleSerializer, ExternalMatchSerializer
from .permissions import HasAPIKey
# from apis.views import import_donors, find_matching_donors
import logging
from django.contrib.auth.hashers import make_password
from apis.utils import process_donor_import_logic, execute_match_search_logic
logger = logging.getLogger(__name__)

class GenerateAPIKeyView(generics.GenericAPIView):
    serializer_class = APIKeyCreateSerializer
    permission_classes = [IsAdminUser]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        if APIKey.objects.filter(hospital_email=email).exists():
            return Response(
                {"error": f"An API key already exists for the email: {email}"},
                status=status.HTTP_409_CONFLICT
            )

        api_key = APIKey.objects.create(
            hospital_email=email,
            created_by=request.user
        )

        send_mail(
            'Your Embryva Platform API Key',
            f'You have been issued an API key for the Embryva platform. Your key is: {api_key.key}',
            settings.DEFAULT_FROM_EMAIL,
            [api_key.hospital_email],
            fail_silently=False,
        )

        # Return the data for the newly created key.
        display_serializer = APIKeySerializer(api_key)
        return Response(display_serializer.data, status=status.HTTP_201_CREATED)

# class ExternalDonorImportView(generics.GenericAPIView):
#     permission_classes = [HasAPIKey]

#     def post(self, request, *args, **kwargs):
#         # FIX: Pass the underlying Django HttpRequest (request._request)
#         return import_donors(request._request)


# class ExternalMatchView(generics.GenericAPIView):
#     serializer_class = ExternalMatchSerializer
#     permission_classes = [HasAPIKey]

#     def post(self, request, *args, **kwargs):
#         # FIX: Pass the underlying Django HttpRequest (request._request)
#         return find_matching_donors(request._request)
    
class ToggleAPIKeyStatusView(generics.UpdateAPIView):
    queryset = APIKey.objects.all()
    serializer_class = APIKeyToggleSerializer
    permission_classes = [IsAdminUser]
    lookup_field = 'id'

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        status_message = "activated" if instance.is_active else "deactivated"
        return Response(
            {"message": f"API Key has been successfully {status_message}."},
            status=status.HTTP_200_OK
        )
    
class ExternalDonorImportView(generics.GenericAPIView):
    permission_classes = [HasAPIKey]
    serializer_class = DonorImportSerializer

    def post(self, request, *args, **kwargs):
        api_key_str = request.headers.get('X-API-Key')
        try:
            api_key = APIKey.objects.select_related('clinic').get(key=api_key_str)
        except APIKey.DoesNotExist:
            return Response({"error": "Invalid API Key"}, status=status.HTTP_403_FORBIDDEN)

        # "Just-in-Time" Onboarding Logic
        if not api_key.clinic:
            logger.info(f"First-time import for {api_key.hospital_email}. Creating clinic account.")
            try:
                clinic_user, created = User.objects.get_or_create(
                    email=api_key.hospital_email,
                    defaults={
                        'user_type': 'clinic',
                        'first_name': f"Clinic",
                        'last_name': f"({api_key.hospital_email})",
                        'password': make_password(secrets.token_urlsafe(16)),
                        'is_active': True,
                        'is_verified': True,
                    }
                )
                if created:
                    logger.info(f"New clinic user created for {clinic_user.email}")
                
                api_key.clinic = clinic_user
                api_key.save()
            except Exception as e:
                logger.error(f"Failed to create clinic user for {api_key.hospital_email}: {e}")
                return Response({"error": "Could not set up hospital account. Please contact support."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        clinic_user = api_key.clinic

        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        file = serializer.validated_data['file']
        
        result = process_donor_import_logic(file, clinic_user)
        
        response_status = result.pop('status', 200)
        return Response(result, status=response_status)


class ExternalMatchView(generics.GenericAPIView):
    serializer_class = ExternalMatchSerializer
    permission_classes = [HasAPIKey]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Call the refactored, reusable matching logic.
        result = execute_match_search_logic(serializer.validated_data)

        response_status = result.pop('status', 200)
        return Response(result, status=response_status)