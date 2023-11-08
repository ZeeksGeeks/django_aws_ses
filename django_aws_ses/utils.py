import base64
import logging
import time
import re
import dns.resolver
from telnetlib import Telnet
from builtins import str as text
from builtins import bytes
from io import StringIO
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import smart_str
from django.dispatch.dispatcher import receiver
from django.db.models import Count

from django.contrib.auth import get_user_model # If used custom user model
User = get_user_model()

from . import settings
from . import signals
from .models import (
    BounceRecord,
    ComplaintRecord,
    BlackListedDomains,
    SendRecord,
    ) 

logger = settings.logger


class BounceMessageVerifier(object):
    """
    A utility class for validating bounce messages

    See: http://docs.amazonwebservices.com/sns/latest/gsg/SendMessageToHttp.verify.signature.html
    """

    def __init__(self, bounce_dict):
        """
        Creates a new bounce message from the given dict.
        """
        self._data = bounce_dict
        self._verified = None

    def is_verified(self):
        """
        Verifies an SES bounce message.

        """
        if self._verified is None:
            signature = self._data.get('Signature')
            if not signature:
                self._verified = False
                return self._verified

            # Decode the signature from base64
            signature = bytes(base64.b64decode(signature))

            # Get the message to sign
            sign_bytes = self._get_bytes_to_sign()
            if not sign_bytes:
                self._verified = False
                return self._verified

            if not self.certificate:
                self._verified = False
                return self._verified

            # Extract the public key
            pkey = self.certificate.get_pubkey()

            # Use the public key to verify the signature.
            pkey.verify_init()
            pkey.verify_update(sign_bytes)
            verify_result = pkey.verify_final(signature)

            self._verified = verify_result == 1

        return self._verified

    @property
    def certificate(self):
        """
        Retrieves the certificate used to sign the bounce message.

        TODO: Cache the certificate based on the cert URL so we don't have to
        retrieve it for each bounce message. *We would need to do it in a
        secure way so that the cert couldn't be overwritten in the cache*
        """
        if not hasattr(self, '_certificate'):
            cert_url = self._get_cert_url()
            # Only load certificates from a certain domain?
            # Without some kind of trusted domain check, any old joe could
            # craft a bounce message and sign it using his own certificate
            # and we would happily load and verify it.

            if not cert_url:
                self._certificate = None
                return self._certificate

            try:
                import requests
            except ImportError:
                raise ImproperlyConfigured(
                    "`requests` is required for bounce message verification. "
                    "Please consider installing the `django-ses` with the "
                    "`bounce` extra - e.g. `pip install django-ses[bounce]`."
                )

            try:
                from M2Crypto import X509
            except ImportError:
                raise ImproperlyConfigured(
                    "`M2Crypto` is required for bounce message verification. "
                    "Please consider installing the `django-ses` with the "
                    "`bounce` extra - e.g. `pip install django-ses[bounce]`."
                )

            # We use requests because it verifies the https certificate
            # when retrieving the signing certificate. If https was somehow
            # hijacked then all bets are off.
            response = requests.get(cert_url)
            if response.status_code != 200:
                logger.warning(u'Could not download certificate from %s: "%s"', cert_url, response.status_code)
                self._certificate = None
                return self._certificate

            # Handle errors loading the certificate.
            # If the certificate is invalid then return
            # false as we couldn't verify the message.
            try:
                self._certificate = X509.load_cert_string(response.content)
            except X509.X509Error as e:
                logger.warning(u'Could not load certificate from %s: "%s"', cert_url, e)
                self._certificate = None

        return self._certificate

    def _get_cert_url(self):
        """
        Get the signing certificate URL.
        Only accept urls that match the domains set in the
        AWS_SNS_BOUNCE_CERT_TRUSTED_DOMAINS setting. Sub-domains
        are allowed. i.e. if amazonaws.com is in the trusted domains
        then sns.us-east-1.amazonaws.com will match.
        """
        cert_url = self._data.get('SigningCertURL')
        if cert_url:
            if cert_url.startswith('https://'):
                url_obj = urlparse(cert_url)
                for trusted_domain in settings.BOUNCE_CERT_DOMAINS:
                    parts = trusted_domain.split('.')
                    if url_obj.netloc.split('.')[-len(parts):] == parts:
                        return cert_url
            logger.warning(u'Untrusted certificate URL: "%s"', cert_url)
        else:
            logger.warning(u'No signing certificate URL: "%s"', cert_url)
        return None

    def _get_bytes_to_sign(self):
        """
        Creates the message used for signing SNS notifications.
        This is used to verify the bounce message when it is received.
        """

        # Depending on the message type the fields to add to the message
        # differ so we handle that here.
        msg_type = self._data.get('Type')
        if msg_type == 'Notification':
            fields_to_sign = [
                'Message',
                'MessageId',
                'Subject',
                'Timestamp',
                'TopicArn',
                'Type',
            ]
        elif (msg_type == 'SubscriptionConfirmation' or
              msg_type == 'UnsubscribeConfirmation'):
            fields_to_sign = [
                'Message',
                'MessageId',
                'SubscribeURL',
                'Timestamp',
                'Token',
                'TopicArn',
                'Type',
            ]
        else:
            # Unrecognized type
            logger.warning(u'Unrecognized SNS message Type: "%s"', msg_type)
            return None

        outbytes = StringIO()
        for field_name in fields_to_sign:
            field_value = smart_str(self._data.get(field_name, ''),
                                    errors="replace")
            if field_value:
                outbytes.write(text(field_name))
                outbytes.write(text("\n"))
                outbytes.write(text(field_value))
                outbytes.write(text("\n"))

        response = outbytes.getvalue()
        return bytes(response, 'utf-8')


def verify_bounce_message(msg):
    """
    Verify an SES/SNS bounce notification message.
    """
    verifier = BounceMessageVerifier(msg)
    return verifier.is_verified()

@receiver(signals.email_pre_send)
def receiver_email_pre_send(sender, message=None, **kwargs):
    #logger.info("receiver_email_pre_send received signal")
    pass

def filter_recipiants(recipiant_list):
    logger.info("Starting filter_recipiants: %s" % recipiant_list)
    
    if type(recipiant_list) != type([]):
        logger.info("putting emails into a list")
        recipiant_list = [recipiant_list]
    
    if len(recipiant_list) > 0:
        recipiant_list = filter_recipiants_with_unsubscribe(recipiant_list)     
            
    if len(recipiant_list) > 0:
        recipiant_list = filter_recipiants_with_complaint_records(recipiant_list)
            
    if len(recipiant_list) > 0:
        recipiant_list = filter_recipiants_with_bounce_records(recipiant_list)
        
    if len(recipiant_list) > 0:
        recipiant_list = filter_recipiants_with_validater_email_domain(recipiant_list)

    logger.info("recipiant list after filter_recipiants: %s" % recipiant_list)
    return recipiant_list

def filter_recipiants_with_unsubscribe(recipiant_list):
    """
    filter message recipiants so we don't send emails to any email that have Unsubscribude
    """
    #logger.info("unsubscribe filter running")
    
    #logger.info("message.recipients() befor blacklist_emails filter: %s" % recipiant_list)
    blacklist_emails = list(set([record.email for record in User.objects.filter(aws_ses__unsubscribe=True)]))       

    if blacklist_emails:
        return filter_recipiants_with_blacklist(recipiant_list, blacklist_emails)
    else:
        return recipiant_list
    
def filter_recipiants_with_complaint_records(recipiant_list):
    """
    filter message recipiants so we don't send emails to any email that have a ComplaintRecord
    """
    #logger.info("complaint_records filter running")
    
    #logger.info("message.recipients() befor blacklist_emails filter: %s" % recipiant_list)
    blacklist_emails = list(set([record.email for record in ComplaintRecord.objects.filter(email__isnull=False)]))       
    
    if blacklist_emails:
        return filter_recipiants_with_blacklist(recipiant_list, blacklist_emails)
    else:
        return recipiant_list    

def filter_recipiants_with_bounce_records(recipiant_list):
    """
    filter message recipiants so we dont send emails to any email that has more BounceRecord
    the SES_BOUNCE_LIMIT
    """
    #logger.info("bounce_records filter running")
    
    #logger.info("message.recipients() befor blacklist_emails filter: %s" % recipiant_list)
    
    blacklist_emails = list(set([record.email for record in BounceRecord.objects.filter(email__isnull=False).annotate(total=Count('email')).filter(total__gte=settings.SES_BOUNCE_LIMIT)]))
    
    if blacklist_emails:
        return filter_recipiants_with_blacklist(recipiant_list, blacklist_emails)
    else:
        return recipiant_list
    
def filter_recipiants_with_blacklist(recipiant_list, blacklist_emails):
    """
    filter message recipiants with a list of emails you dont want to email
    """
    filtered_recipiant_list = [email for email in recipiant_list if email not in blacklist_emails] 
    
    return filtered_recipiant_list

def filter_recipiants_with_validater_email_domain(recipiant_list):
    debug_flag = True
    
    sent_list = [e.destination for e in SendRecord.objects.filter(destination__in=recipiant_list).distinct("destination")]
    
    test_list = [e for e in recipiant_list if e not in sent_list]

    for e in test_list:

        if not validater_email_domain(e):
           recipiant_list.remove(e)
             
    return recipiant_list

def validater_email_domain(email):
    
    if email.find("@") < 1:
        
        return False
    domain = email.split("@")[-1]
    
    if BlackListedDomains.objects.filter(domain=domain).count() > 0:
        return False
    
    records = []
    try:
        records = dns.resolver.query(domain, 'MX')
    except dns.resolver.NoNameservers as e:
        return False
    
    except dns.resolver.NoAnswer as e:
        return False
    
    except dns.resolver.NXDOMAIN as e:
        return False
    
    except dns.resolver.LifetimeTimeout as e:
        return False
    
    if len(records) < 1:
        return False
    
    return True

def emailIsValid(email):

    resp = False
    regex = re.compile(r'([A-Za-z0-9]+[.\-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(.[A-Z|a-z]{2,})+')
    if re.fullmatch(regex, email):
        resp =  True

    return resp

def validate_email(email):

    if not emailIsValid(email):
        return False
    
    if BounceRecord.objects.filter(email=email).count() >= settings.SES_BOUNCE_LIMIT:
        return False
    
    if ComplaintRecord.objects.filter(email=email).count() > 0:
        return False
    
    return validater_email_domain(email)