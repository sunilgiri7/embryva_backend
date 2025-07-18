from django.urls import re_path

from apis.services import websocket_consumers

websocket_urlpatterns = [
    re_path(r'ws/realtime-matching/$', websocket_consumers.RealtimeMatchingConsumer.as_asgi()),
]