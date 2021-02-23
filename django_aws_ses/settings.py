from django.conf import settings

import logging

from .models import (
    AwsSesSettings
    )
try:
    aws_ses_Settings, c = AwsSesSettings.objects.get_or_create(site_id=settings.SITE_ID)
except Exception as e:
    print("AwsSesSettings does not exist: error: %s" % e)
else:
    __all__ = ('ACCESS_KEY', 'SECRET_KEY', 'AWS_SES_REGION_NAME',
               'AWS_SES_REGION_ENDPOINT', 'AWS_SES_AUTO_THROTTLE',
               'AWS_SES_RETURN_PATH', 'DKIM_DOMAIN', 'DKIM_PRIVATE_KEY',
               'DKIM_SELECTOR', 'DKIM_HEADERS', 'TIME_ZONE', 'BASE_DIR',
               'BOUNCE_LIMIT','SES_BACKEND_DEBUG','SES_BACKEND_DEBUG_LOGFILE_PATH',
               'SES_BACKEND_DEBUG_LOGFILE_FORMATTER')
    
    BASE_DIR = getattr(settings, 'BASE_DIR', None)
    
    if not BASE_DIR:
        raise RuntimeError('No BASE_DIR defined in project settings, django_aws_ses requires BASE_DIR to be defined and pointed at your root directory. i.e. BASE_DIR = os.path.dirname(os.path.abspath(__file__))')
    
    DEFAULT_FROM_EMAIL = getattr(settings, 'DEFAULT_FROM_EMAIL', 'no_reply@%s' % aws_ses_Settings.site.domain)
    
    HOME_URL = getattr(settings, 'HOME_URL', '')
    
    UNSUBSCRIBE_TEMPLET = getattr(settings, 'UNSUBSCRIBE_TEMPLET', 'django_aws_ses/unsebscribe.html')
    BASE_TEMPLET = getattr(settings, 'UNSUBSCRIBE_TEMPLET', 'django_aws_ses/base.html')
    
    ACCESS_KEY = aws_ses_Settings.access_key or getattr(settings, 'AWS_SES_ACCESS_KEY_ID',getattr(settings, 'AWS_ACCESS_KEY_ID', None))
    
    SECRET_KEY = aws_ses_Settings.secret_key or getattr(settings, 'AWS_SES_SECRET_ACCESS_KEY',getattr(settings, 'AWS_SECRET_ACCESS_KEY', None))
    
    AWS_SES_REGION_NAME = aws_ses_Settings.region_name or getattr(settings, 'AWS_SES_REGION_NAME',getattr(settings, 'AWS_DEFAULT_REGION', 'us-east-1'))
    
    AWS_SES_REGION_ENDPOINT = aws_ses_Settings.region_endpoint or getattr(settings, 'AWS_SES_REGION_ENDPOINT','email.us-east-1.amazonaws.com')
    
    AWS_SES_REGION_ENDPOINT_URL = getattr(settings, 'AWS_SES_REGION_ENDPOINT_URL','https://' + AWS_SES_REGION_ENDPOINT)
    
    AWS_SES_AUTO_THROTTLE = getattr(settings, 'AWS_SES_AUTO_THROTTLE', 0.5)
    AWS_SES_RETURN_PATH = getattr(settings, 'AWS_SES_RETURN_PATH', None)
    AWS_SES_CONFIGURATION_SET = getattr(settings, 'AWS_SES_CONFIGURATION_SET', None)
    
    DKIM_DOMAIN = getattr(settings, "DKIM_DOMAIN", None)
    DKIM_PRIVATE_KEY = getattr(settings, 'DKIM_PRIVATE_KEY', None)
    DKIM_SELECTOR = getattr(settings, 'DKIM_SELECTOR', 'ses')
    DKIM_HEADERS = getattr(settings, 'DKIM_HEADERS', ('From', 'To', 'Cc', 'Subject'))
    
    TIME_ZONE = settings.TIME_ZONE
    
    VERIFY_BOUNCE_SIGNATURES = getattr(settings, 'AWS_SES_VERIFY_BOUNCE_SIGNATURES', True)
    
    # Domains that are trusted when retrieving the certificate
    # used to sign bounce messages.
    BOUNCE_CERT_DOMAINS = getattr(settings, 'AWS_SNS_BOUNCE_CERT_TRUSTED_DOMAINS', (
        'amazonaws.com',
        'amazon.com',
    ))
    
    SES_BOUNCE_LIMIT = getattr(settings,'BOUNCE_LIMT', 1)
    
    SES_BACKEND_DEBUG = getattr(settings,'SES_BACKEND_DEBUG', False)
        
    SES_BACKEND_DEBUG_LOGFILE_PATH = getattr(settings,'SES_BACKEND_DEBUG_LOGFILE_PATH', '%s/aws_ses.log' % BASE_DIR)
    
    SES_BACKEND_DEBUG_LOGFILE_FORMATTER = getattr(settings,'SES_BACKEND_DEBUG_LOGFILE_FORMATTER', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    logger = logging.getLogger('django_aws_ses')
    # logger.setLevel(logging.WARNING)
    if SES_BACKEND_DEBUG:
        logger.setLevel(logging.INFO)
        # create a file handler
        if SES_BACKEND_DEBUG_LOGFILE_PATH:
            handler = logging.FileHandler(SES_BACKEND_DEBUG_LOGFILE_PATH)
            handler.setLevel(logging.INFO)
            # create a logging format
            formatter = logging.Formatter(SES_BACKEND_DEBUG_LOGFILE_FORMATTER)
            handler.setFormatter(formatter)
            # add the handlers to the logger
            logger.addHandler(handler)
            #logger.info('something we are logging')
