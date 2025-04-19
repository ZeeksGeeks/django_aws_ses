import logging
import os

from django.conf import settings as django_settings
from django.contrib.sites.models import Site
from django.core.exceptions import ImproperlyConfigured
from django.db.utils import DatabaseError

from .models import AwsSesSettings

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
    'SES_BOUNCE_LIMIT': 1,
    'SES_BACKEND_DEBUG': False,
    'SES_BACKEND_DEBUG_LOGFILE_FORMATTER': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'DEFAULT_FROM_EMAIL': 'no-reply@example.com',
    'UNSUBSCRIBE_TEMPLATE': 'django_aws_ses/unsubscribe.html',
    'BASE_TEMPLATE': 'django_aws_ses/base.html',
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
    'logger',
)


def get_aws_ses_settings():
    """Retrieve AwsSesSettings from the database for the current site.

    Returns:
        AwsSesSettings: The settings object, or None if not found.
    """
    if getattr(django_settings, 'TESTING', False):
        return None  # Skip query during testing to avoid database errors
    try:
        return AwsSesSettings.objects.get(site_id=django_settings.SITE_ID)
    except (AwsSesSettings.DoesNotExist, AttributeError, DatabaseError) as e:
        logger.warning(f"Failed to retrieve AwsSesSettings: {e}")
        return None


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

# Fetch AwsSesSettings from database
aws_ses_settings = get_aws_ses_settings()

# AWS Credentials
if getattr(django_settings, 'TESTING', False):
    ACCESS_KEY = 'test-key'
    SECRET_KEY = 'test-secret'
else:
    ACCESS_KEY = aws_ses_settings.access_key if aws_ses_settings else getattr(
        django_settings, 'AWS_SES_ACCESS_KEY_ID', getattr(django_settings, 'AWS_ACCESS_KEY_ID', None)
    )
    SECRET_KEY = aws_ses_settings.secret_key if aws_ses_settings else getattr(
        django_settings, 'AWS_SES_SECRET_ACCESS_KEY', getattr(django_settings, 'AWS_SECRET_ACCESS_KEY', None)
    )

    if not (ACCESS_KEY and SECRET_KEY):
        raise ImproperlyConfigured(
            "AWS SES credentials (AWS_SES_ACCESS_KEY_ID and AWS_SES_SECRET_ACCESS_KEY) must be provided "
            "via AwsSesSettings or Django settings."
        )

# AWS SES Configuration
AWS_SES_REGION_NAME = aws_ses_settings.region_name if aws_ses_settings else getattr(
    django_settings, 'AWS_SES_REGION_NAME', DEFAULTS['AWS_SES_REGION_NAME']
)
AWS_SES_REGION_ENDPOINT = aws_ses_settings.region_endpoint if aws_ses_settings else getattr(
    django_settings, 'AWS_SES_REGION_ENDPOINT', DEFAULTS['AWS_SES_REGION_ENDPOINT']
)
AWS_SES_AUTO_THROTTLE = getattr(django_settings, 'AWS_SES_AUTO_THROTTLE', DEFAULTS['AWS_SES_AUTO_THROTTLE'])
AWS_SES_RETURN_PATH = getattr(django_settings, 'AWS_SES_RETURN_PATH', DEFAULTS['AWS_SES_RETURN_PATH'])
AWS_SES_CONFIGURATION_SET = getattr(django_settings, 'AWS_SES_CONFIGURATION_SET', DEFAULTS['AWS_SES_CONFIGURATION_SET'])

# DKIM Settings
DKIM_DOMAIN = getattr(django_settings, 'DKIM_DOMAIN', None)
DKIM_PRIVATE_KEY = getattr(django_settings, 'DKIM_PRIVATE_KEY', None)
DKIM_SELECTOR = getattr(django_settings, 'DKIM_SELECTOR', DEFAULTS['DKIM_SELECTOR'])
DKIM_HEADERS = getattr(django_settings, 'DKIM_HEADERS', DEFAULTS['DKIM_HEADERS'])

# Email Settings
try:
    site = Site.objects.get_current()
    DEFAULT_FROM_EMAIL = getattr(django_settings, 'DEFAULT_FROM_EMAIL', f"no-reply@{site.domain}")
except Site.DoesNotExist:
    DEFAULT_FROM_EMAIL = getattr(django_settings, 'DEFAULT_FROM_EMAIL', DEFAULTS['DEFAULT_FROM_EMAIL'])
    logger.warning(
        f"Django sites framework not configured. Using DEFAULT_FROM_EMAIL: {DEFAULT_FROM_EMAIL}. "
        "Configure the Site model or set DEFAULT_FROM_EMAIL in settings."
    )

# Other Settings
HOME_URL = getattr(django_settings, 'HOME_URL', '/')
UNSUBSCRIBE_TEMPLATE = getattr(django_settings, 'UNSUBSCRIBE_TEMPLATE', DEFAULTS['UNSUBSCRIBE_TEMPLATE'])
BASE_TEMPLATE = getattr(django_settings, 'BASE_TEMPLATE', DEFAULTS['BASE_TEMPLATE'])
VERIFY_BOUNCE_SIGNATURES = getattr(django_settings, 'AWS_SES_VERIFY_BOUNCE_SIGNATURES', DEFAULTS['VERIFY_BOUNCE_SIGNATURES'])
BOUNCE_CERT_DOMAINS = getattr(django_settings, 'AWS_SNS_BOUNCE_CERT_TRUSTED_DOMAINS', DEFAULTS['BOUNCE_CERT_DOMAINS'])
SES_BOUNCE_LIMIT = getattr(django_settings, 'SES_BOUNCE_LIMIT', DEFAULTS['SES_BOUNCE_LIMIT'])
SES_BACKEND_DEBUG = getattr(django_settings, 'SES_BACKEND_DEBUG', DEFAULTS['SES_BACKEND_DEBUG'])
SES_BACKEND_DEBUG_LOGFILE_PATH = getattr(
    django_settings, 'SES_BACKEND_DEBUG_LOGFILE_PATH', os.path.join(BASE_DIR, 'aws_ses.log')
)
SES_BACKEND_DEBUG_LOGFILE_FORMATTER = getattr(
    django_settings, 'SES_BACKEND_DEBUG_LOGFILE_FORMATTER', DEFAULTS['SES_BACKEND_DEBUG_LOGFILE_FORMATTER']
)
TIME_ZONE = django_settings.TIME_ZONE

# Configure logger with final settings
logger = configure_logger(SES_BACKEND_DEBUG, SES_BACKEND_DEBUG_LOGFILE_PATH, SES_BACKEND_DEBUG_LOGFILE_FORMATTER)