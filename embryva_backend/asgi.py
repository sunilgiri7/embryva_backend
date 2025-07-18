# asgi.py

import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'embryva_backend.settings')

import django
django.setup()  # <-- Important to load the app registry early

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from apis.websocket_routing import websocket_urlpatterns
from apis.services.websocket_middleware import JWTAuthMiddleware

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": JWTAuthMiddleware(
        URLRouter(websocket_urlpatterns)
    ),
})
