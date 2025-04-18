from django.apps import AppConfig


class DjangoAwsSesBackendConfig(AppConfig):
    """Configuration for the Django AWS SES email backend app."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_aws_ses'
    verbose_name = 'AWS SES Email Backend'