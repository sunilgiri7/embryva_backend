from rest_framework.permissions import BasePermission
from .models import APIKey

class HasAPIKey(BasePermission):
    def has_permission(self, request, view):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return False
        
        try:
            key = APIKey.objects.get(key=api_key)
            return key.is_active
        except APIKey.DoesNotExist:
            return False