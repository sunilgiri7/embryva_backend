from django.urls import path
from .views import (
    GenerateAPIKeyView,
    ExternalDonorImportView,
    ExternalMatchView,
    ToggleAPIKeyStatusView,
)

urlpatterns = [
    path('keys/generate/', GenerateAPIKeyView.as_view(), name='generate-api-key'),
    path('keys/<uuid:id>/toggle/', ToggleAPIKeyStatusView.as_view(), name='toggle-api-key-status'),
    path('donors/import/', ExternalDonorImportView.as_view(), name='external-donor-import'),
    path('donors/match/', ExternalMatchView.as_view(), name='external-donor-match'),
]