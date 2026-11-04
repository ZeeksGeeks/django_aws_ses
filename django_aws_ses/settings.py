import logging
import os

from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured

# Default configuration values
DEFAULTS = {
    'AWS_SES_REGION_NAME': 'us-east-1',
    'AWS_SES_REGION_ENDPOINT': 'email.us-east-1.amazonaws.com',
    'AWS_SES_AUTO_THROTTLE': 0.5,
    'AWS_SES_RETURN_PATH': None,
    'AWS_SES_CONFIGURATION_SET': None,
    'DKIM_SELECTOR': 'ses',
    'DKIM_HEADERS': ('From', 'To', 'Cc', 'Subject'),
    'VERIFY_BOUNCE_SIGNATURES': True,
    'BOUNCE_CERT_DOMAINS': ('amazonaws.com', 'amazon.com'),
    'BOUNCE_TOPIC_ARNS': (),
    'SES_BOUNCE_LIMIT': 1,
    'SES_BACKEND_DEBUG': False,
    'SES_BACKEND_DEBUG_LOGFILE_FORMATTER': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'DEFAULT_FROM_EMAIL': 'no-reply@example.com',
    'UNSUBSCRIBE_TEMPLATE': 'django_aws_ses/unsubscribe.html',
    'BASE_TEMPLATE': 'django_aws_ses/base.html',
    'UNSUBSCRIBE_URL': None,
    'UNSUBSCRIBE_BASE_URL': None,
    'AUTO_LIST_UNSUBSCRIBE': False,
    'UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS': True,
    'FILTER_EMAIL_UNSUBSCRIBES': False,
}

# Exported settings
__all__ = (
    'ACCESS_KEY',
    'SECRET_KEY',
    'AWS_SES_REGION_NAME',
    'AWS_SES_REGION_ENDPOINT',
    'AWS_SES_AUTO_THROTTLE',
    'AWS_SES_RETURN_PATH',
    'AWS_SES_CONFIGURATION_SET',
    'DKIM_DOMAIN',
    'DKIM_PRIVATE_KEY',
    'DKIM_SELECTOR',
    'DKIM_HEADERS',
    'TIME_ZONE',
    'BASE_DIR',
    'SES_BOUNCE_LIMIT',
    'SES_BACKEND_DEBUG',
    'SES_BACKEND_DEBUG_LOGFILE_PATH',
    'SES_BACKEND_DEBUG_LOGFILE_FORMATTER',
    'DEFAULT_FROM_EMAIL',
    'HOME_URL',
    'UNSUBSCRIBE_TEMPLATE',
    'BASE_TEMPLATE',
    'VERIFY_BOUNCE_SIGNATURES',
    'BOUNCE_CERT_DOMAINS',
    'BOUNCE_TOPIC_ARNS',
    'AWS_SES_UNSUBSCRIBE_URL',
    'AWS_SES_UNSUBSCRIBE_BASE_URL',
    'AWS_SES_AUTO_LIST_UNSUBSCRIBE',
    'AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS',
    'AWS_SES_FILTER_EMAIL_UNSUBSCRIBES',
    'logger',
)

def configure_logger(debug, log_file_path, formatter):
    """Configure the logger for the AWS SES app.

    Args:
        debug (bool): Enable debug logging if True.
        log_file_path (str): Path to the log file.
        formatter (str): Logging formatter string.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger('django_aws_ses')
    logger.setLevel(logging.DEBUG if debug else logging.WARNING)

    if debug and log_file_path:
        log_dir = os.path.dirname(log_file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        try:
            handler = logging.FileHandler(log_file_path)
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(formatter)
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        except OSError as e:
            logger.error(f"Failed to configure log file {log_file_path}: {e}")

    return logger


# Initialize logger
logger = logging.getLogger('django_aws_ses')

# Validate BASE_DIR
BASE_DIR = getattr(django_settings, 'BASE_DIR', None)
if not BASE_DIR:
    raise ImproperlyConfigured("BASE_DIR must be defined in Django settings.")

# AWS Credentials
if getattr(django_settings, 'TESTING', False):
    ACCESS_KEY = 'test-key'
    SECRET_KEY = 'test-secret'
else:
    ACCESS_KEY = getattr(django_settings, 'AWS_ACCESS_KEY_ID', None)
    SECRET_KEY = getattr(django_settings, 'AWS_SECRET_ACCESS_KEY', None)

# AWS SES Configuration
AWS_SES_REGION_NAME = getattr(django_settings, 'AWS_SES_REGION_NAME', DEFAULTS['AWS_SES_REGION_NAME'])
AWS_SES_REGION_ENDPOINT = getattr(django_settings, 'AWS_SES_REGION_ENDPOINT', DEFAULTS['AWS_SES_REGION_ENDPOINT'])
AWS_SES_AUTO_THROTTLE = getattr(django_settings, 'AWS_SES_AUTO_THROTTLE', DEFAULTS['AWS_SES_AUTO_THROTTLE'])
AWS_SES_RETURN_PATH = getattr(django_settings, 'AWS_SES_RETURN_PATH', DEFAULTS['AWS_SES_RETURN_PATH'])
AWS_SES_CONFIGURATION_SET = getattr(django_settings, 'AWS_SES_CONFIGURATION_SET', DEFAULTS['AWS_SES_CONFIGURATION_SET'])

# DKIM Settings
DKIM_DOMAIN = getattr(django_settings, 'DKIM_DOMAIN', None)
DKIM_PRIVATE_KEY = getattr(django_settings, 'DKIM_PRIVATE_KEY', None)
DKIM_SELECTOR = getattr(django_settings, 'DKIM_SELECTOR', DEFAULTS['DKIM_SELECTOR'])
DKIM_HEADERS = getattr(django_settings, 'DKIM_HEADERS', DEFAULTS['DKIM_HEADERS'])

# Email Settings
DEFAULT_FROM_EMAIL = getattr(django_settings, 'DEFAULT_FROM_EMAIL', DEFAULTS['DEFAULT_FROM_EMAIL'])


# Other Settings
HOME_URL = getattr(django_settings, 'HOME_URL', '/')
UNSUBSCRIBE_TEMPLATE = getattr(django_settings, 'UNSUBSCRIBE_TEMPLATE', DEFAULTS['UNSUBSCRIBE_TEMPLATE'])
BASE_TEMPLATE = getattr(django_settings, 'BASE_TEMPLATE', DEFAULTS['BASE_TEMPLATE'])
VERIFY_BOUNCE_SIGNATURES = getattr(django_settings, 'AWS_SES_VERIFY_BOUNCE_SIGNATURES', DEFAULTS['VERIFY_BOUNCE_SIGNATURES'])
BOUNCE_CERT_DOMAINS = getattr(django_settings, 'AWS_SNS_BOUNCE_CERT_TRUSTED_DOMAINS', DEFAULTS['BOUNCE_CERT_DOMAINS'])
# SNS topic ARNs the bounce endpoint accepts messages from. Empty accepts any topic.
# A single string is treated as a one-item list, so `in` never does a substring match.
BOUNCE_TOPIC_ARNS = getattr(django_settings, 'AWS_SES_BOUNCE_TOPIC_ARNS', DEFAULTS['BOUNCE_TOPIC_ARNS'])
if isinstance(BOUNCE_TOPIC_ARNS, str):
    BOUNCE_TOPIC_ARNS = (BOUNCE_TOPIC_ARNS,)
BOUNCE_TOPIC_ARNS = tuple(BOUNCE_TOPIC_ARNS or ())
SES_BOUNCE_LIMIT = getattr(django_settings, 'SES_BOUNCE_LIMIT', DEFAULTS['SES_BOUNCE_LIMIT'])
SES_BACKEND_DEBUG = getattr(django_settings, 'SES_BACKEND_DEBUG', DEFAULTS['SES_BACKEND_DEBUG'])
SES_BACKEND_DEBUG_LOGFILE_PATH = getattr(
    django_settings, 'SES_BACKEND_DEBUG_LOGFILE_PATH', os.path.join(BASE_DIR, 'aws_ses.log')
)
SES_BACKEND_DEBUG_LOGFILE_FORMATTER = getattr(
    django_settings, 'SES_BACKEND_DEBUG_LOGFILE_FORMATTER', DEFAULTS['SES_BACKEND_DEBUG_LOGFILE_FORMATTER']
)
TIME_ZONE = django_settings.TIME_ZONE

# Unsubscribe Settings
# Where unsubscribe links point: a format string containing '{token}' or a callable taking the token.
# None keeps the library's own confirmation page.
AWS_SES_UNSUBSCRIBE_URL = getattr(django_settings, 'AWS_SES_UNSUBSCRIBE_URL', DEFAULTS['UNSUBSCRIBE_URL'])
# Absolute origin of this backend (e.g. 'https://api.example.com'); required for RFC 8058 one-click URLs.
AWS_SES_UNSUBSCRIBE_BASE_URL = getattr(django_settings, 'AWS_SES_UNSUBSCRIBE_BASE_URL', DEFAULTS['UNSUBSCRIBE_BASE_URL'])
# Add List-Unsubscribe headers automatically to single-recipient messages mapped to a user/EmailUnsubscribe.
AWS_SES_AUTO_LIST_UNSUBSCRIBE = getattr(django_settings, 'AWS_SES_AUTO_LIST_UNSUBSCRIBE', DEFAULTS['AUTO_LIST_UNSUBSCRIBE'])
# Accept unsubscribe tokens issued by django_aws_ses <= 0.1.6 (they embed the email address).
AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS = getattr(
    django_settings, 'AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS', DEFAULTS['UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS']
)
# Also drop recipients whose EmailUnsubscribe record is marked unsubscribed.
AWS_SES_FILTER_EMAIL_UNSUBSCRIBES = getattr(
    django_settings, 'AWS_SES_FILTER_EMAIL_UNSUBSCRIBES', DEFAULTS['FILTER_EMAIL_UNSUBSCRIBES']
)

# Configure logger with final settings
logger = configure_logger(SES_BACKEND_DEBUG, SES_BACKEND_DEBUG_LOGFILE_PATH, SES_BACKEND_DEBUG_LOGFILE_FORMATTER)