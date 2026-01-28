from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'
    
    def ready(self):
        """Import signals when app is ready"""
        import apps.core.models  # noqa: F401 - Ensures signals are registered
