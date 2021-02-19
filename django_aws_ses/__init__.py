
default_app_config = 'django_aws_ses.apps.DjangoAwsSesBackendConfig'

# When changing this, remember to change it in setup.py
VERSION = (0, 0, 1)
__version__ = '.'.join([str(x) for x in VERSION])
__author__ = 'Ray Jessop'
__all__ = ('Django AWS SES Backend',)
