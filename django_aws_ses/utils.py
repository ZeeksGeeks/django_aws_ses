import base64
import re
import dns.resolver
from io import StringIO
from urllib.parse import urlparse
from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import smart_str
from django.dispatch.dispatcher import receiver
from django.db.models import Count
from django.contrib.auth import get_user_model
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import requests

from . import settings
from . import signals
from .models import (
    BounceRecord,
    ComplaintRecord,
    BlackListedDomains,
    SendRecord,
)

from django.contrib.auth import get_user_model
User = get_user_model()

# Logger setup
logger = settings.logger

class BounceMessageVerifier(object):
    """
    Utility class for validating AWS SES/SNS bounce messages.
    Verifies the message signature using the provided certificate.
    """
    def __init__(self, bounce_dict):
        # Initialize with the bounce message dictionary
        self._data = bounce_dict
        self._verified = None
        self._certificate = None

    def is_verified(self):
        """
        Verifies the signature of an SES bounce message.
        Returns True if the signature is valid, False otherwise.
        """
        if self._verified is None:
            # Extract and decode the signature
            signature = self._data.get('Signature')
            if not signature:
                logger.warning("No signature found in bounce message")
                self._verified = False
                return self._verified

            try:
                signature = base64.b64decode(signature)
            except ValueError:
                logger.warning("Invalid base64 signature")
                self._verified = False
                return self._verified

            # Get the message bytes to verify against
            sign_bytes = self._get_bytes_to_sign()
            if not sign_bytes:
                logger.warning("Could not generate bytes to sign")
                self._verified = False
                return self._verified

            # Load the signing certificate
            certificate = self.certificate
            if not certificate:
                logger.warning("No valid certificate available")
                self._verified = False
                return self._verified

            # Verify the signature using the certificate's public key
            try:
                public_key = certificate.public_key()
                public_key.verify(
                    signature,
                    sign_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA1()  # AWS SNS uses SHA1
                )
                self._verified = True
            except InvalidSignature:
                logger.warning("Signature verification failed: Invalid signature")
                self._verified = False
            except Exception as e:
                logger.warning("Signature verification failed: %s", e)
                self._verified = False

        return self._verified

    @property
    def certificate(self):
        """
        Fetches and loads the X.509 certificate used to sign the bounce message.
        Returns None if the certificate cannot be loaded.
        """
        if self._certificate is None:
            cert_url = self._get_cert_url()
            if not cert_url:
                logger.warning("No valid certificate URL")
                return None

            # Ensure requests is available
            try:
                import requests
            except ImportError:
                raise ImproperlyConfigured(
                    "`requests` is required for bounce message verification. "
                    "Install with `pip install requests`."
                )

            # Ensure cryptography is available
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
            except ImportError:
                raise ImproperlyConfigured(
                    "`cryptography` is required for bounce message verification. "
                    "Install with `pip install cryptography`."
                )

            # Fetch the certificate
            response = requests.get(cert_url)
            if response.status_code != 200:
                logger.warning("Failed to download certificate from %s: %s", cert_url, response.status_code)
                return None

            # Load the certificate
            try:
                self._certificate = x509.load_pem_x509_certificate(response.content, default_backend())
            except Exception as e:
                logger.warning("Failed to load certificate from %s: %s", cert_url, e)
                return None

        return self._certificate

    def _get_cert_url(self):
        """
        Retrieves the certificate URL from the message, ensuring it comes from a trusted domain.
        Returns None if the URL is untrusted or invalid.
        """
        cert_url = self._data.get('SigningCertURL')
        if cert_url and cert_url.startswith('https://'):
            url_obj = urlparse(cert_url)
            for trusted_domain in settings.BOUNCE_CERT_DOMAINS:
                parts = trusted_domain.split('.')
                if url_obj.netloc.split('.')[-len(parts):] == parts:
                    return cert_url
            logger.warning("Untrusted certificate URL: %s", cert_url)
        else:
            logger.warning("No/invalid certificate URL: %s", cert_url)
        return None

    def _get_bytes_to_sign(self):
        """
        Constructs the message bytes to be signed for verification.
        Returns None if the message type is unrecognized.
        """
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
        elif msg_type in ('SubscriptionConfirmation', 'UnsubscribeConfirmation'):
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
            logger.warning("Unrecognized SNS message type: %s", msg_type)
            return None

        outbytes = StringIO()
        for field_name in fields_to_sign:
            field_value = smart_str(self._data.get(field_name, ''), errors="replace")
            if field_value:
                outbytes.write(field_name)
                outbytes.write("\n")
                outbytes.write(field_value)
                outbytes.write("\n")

        return outbytes.getvalue().encode('utf-8')

def verify_bounce_message(msg):
    """
    Verifies an SES/SNS bounce notification message.
    Returns True if valid, False otherwise.
    """
    verifier = BounceMessageVerifier(msg)
    return verifier.is_verified()

@receiver(signals.email_pre_send)
def receiver_email_pre_send(sender, message=None, **kwargs):
    """
    Signal receiver for pre-send email processing.
    Currently a no-op.
    """
    pass

@receiver(signals.email_post_send)
def receiver_email_post_send(sender, message=None, **kwargs):
    """Handle post-send actions (e.g., log success, update metrics)."""
    if message:
        logger.info(f"Email sent successfully to {message.recipients()}")
        # Add custom logic here

def filter_recipients(recipiant_list):
    """
    Filters a list of recipient email addresses to exclude invalid or blacklisted emails.
    """
    logger.info("Starting filter_recipients: %s", recipiant_list)

    # Ensure recipient_list is a list
    if not isinstance(recipiant_list, list):
        logger.info("Converting recipients to list")
        recipiant_list = [recipiant_list]

    if recipiant_list:
        recipiant_list = filter_recipients_with_unsubscribe(recipiant_list)
        recipiant_list = filter_recipients_with_complaint_records(recipiant_list)
        recipiant_list = filter_recipients_with_bounce_records(recipiant_list)
        recipiant_list = filter_recipients_with_validater_email_domain(recipiant_list)

    logger.info("Filtered recipient list: %s", recipiant_list)
    return recipiant_list

def filter_recipients_with_unsubscribe(recipiant_list):
    """
    Removes recipients who have unsubscribed.
    """
    blacklist_emails = list(set([record.email for record in User.objects.filter(aws_ses__unsubscribe=True)]))
    return filter_recipients_with_blacklist(recipiant_list, blacklist_emails) if blacklist_emails else recipiant_list

def filter_recipients_with_complaint_records(recipiant_list):
    """
    Removes recipients with complaint records.
    """
    blacklist_emails = list(set([record.email for record in ComplaintRecord.objects.filter(email__isnull=False)]))
    return filter_recipients_with_blacklist(recipiant_list, blacklist_emails) if blacklist_emails else recipiant_list

def filter_recipients_with_bounce_records(recipiant_list):
    """
    Removes recipients with bounce records exceeding SES_BOUNCE_LIMIT.
    """
    blacklist_emails = list(set([record.email for record in BounceRecord.objects.filter(email__isnull=False)
                                .annotate(total=Count('email')).filter(total__gte=settings.SES_BOUNCE_LIMIT)]))
    return filter_recipients_with_blacklist(recipiant_list, blacklist_emails) if blacklist_emails else recipiant_list

def filter_recipients_with_blacklist(recipiant_list, blacklist_emails):
    """
    Filters out emails from a blacklist.
    """
    return [email for email in recipiant_list if email not in blacklist_emails]

def filter_recipients_with_validater_email_domain(recipiant_list):
    """
    Validates email domains for new recipients.
    """
    sent_list = list(set([e.destination for e in SendRecord.objects.filter(destination__in=recipiant_list).distinct()]))
    test_list = [e for e in recipiant_list if e not in sent_list]

    for e in test_list:
        if not validater_email_domain(e):
            recipiant_list.remove(e)

    return recipiant_list

def validater_email_domain(email):
    """
    Checks if an email's domain has valid MX records and is not blacklisted.
    """
    if email.find("@") < 1:
        return False
    domain = email.split("@")[-1]

    if BlackListedDomains.objects.filter(domain=domain).exists():
        return False

    try:
        records = dns.resolver.query(domain, 'MX')
        return len(records) > 0
    except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        return False

def emailIsValid(email):
    """
    Validates email format using regex.
    """
    regex = re.compile(r'([A-Za-z0-9]+[.\-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(.[A-Z|a-z]{2,})+')
    return bool(re.fullmatch(regex, email))

def validate_email(email):
    """
    Validates an email address for sending.
    Checks format, bounce records, complaints, and domain validity.
    """
    if not emailIsValid(email):
        return False
    if BounceRecord.objects.filter(email=email).count() >= settings.SES_BOUNCE_LIMIT:
        return False
    if ComplaintRecord.objects.filter(email=email).exists():
        return False
    return validater_email_domain(email)