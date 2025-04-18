"""Django AWS SES: A Django email backend for Amazon SES."""

default_app_config = 'django_aws_ses.apps.DjangoAwsSesBackendConfig'

VERSION = (0, 1, 0)
__version__ = '.'.join(str(x) for x in VERSION)
__author__ = 'Ray Jessop'
__all__ = ('SESBackend', 'DjangoAwsSesBackendConfig')