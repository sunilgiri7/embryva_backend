from django.apps import AppConfig


class ApisConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apis'

    def ready(self):
        # Import signals to connect them when the app is ready
        import apis.services.signals