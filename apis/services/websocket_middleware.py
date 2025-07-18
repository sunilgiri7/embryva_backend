from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from urllib.parse import parse_qs
import jwt
from django.conf import settings

User = get_user_model()

@database_sync_to_async
def get_user_from_token(token):
    """Get user from JWT token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user = User.objects.get(id=payload['user_id'])
        return user
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
        return AnonymousUser()

class JWTAuthMiddleware(BaseMiddleware):
    """JWT authentication middleware for WebSocket connections"""
    
    async def __call__(self, scope, receive, send):
        # Get token from query parameters
        query_params = parse_qs(scope['query_string'].decode())
        token = query_params.get('token', [None])[0]
        
        if token:
            scope['user'] = await get_user_from_token(token)
        else:
            scope['user'] = AnonymousUser()
        
        return await super().__call__(scope, receive, send)