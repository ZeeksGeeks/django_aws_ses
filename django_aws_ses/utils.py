import base64
import hashlib
import re
import dns.resolver
from email.utils import parseaddr
from io import StringIO
from urllib.parse import urlparse
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import smart_str
from django.dispatch.dispatcher import receiver
from django.db.models import Count
from django.db.models.functions import Lower
from django.contrib.auth import get_user_model
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from . import settings
from . import signals
from .models import (
    BounceRecord,
    ComplaintRecord,
    BlackListedDomains,
    SendRecord,
    EmailUnsubscribe,
)

User = get_user_model()

# Logger setup
logger = settings.logger

# Marks a message as transactional (password reset, verification code, ...): the
# unsubscribe filter is skipped for it. The header is stripped before sending.
# Setting ``message.aws_ses_transactional = True`` has the same effect.
TRANSACTIONAL_HEADER = 'X-Django-AWS-SES-Transactional'


def normalize_address(address):
    """
    Returns the bare, lower-cased address from a recipient string.
    "Name <User@Example.com>" -> "user@example.com".
    """
    if not address:
        return ''
    return parseaddr(str(address))[1].strip().lower()


def _normalized_addresses(recipiant_list):
    return {a for a in (normalize_address(e) for e in recipiant_list) if a}


def is_transactional(message):
    """
    Returns True if a message opted out of the unsubscribe filter, via the
    ``aws_ses_transactional`` attribute or the TRANSACTIONAL_HEADER header.
    """
    if getattr(message, 'aws_ses_transactional', False):
        return True
    for name, value in (getattr(message, 'extra_headers', None) or {}).items():
        if name.lower() == TRANSACTIONAL_HEADER.lower():
            return str(value).strip().lower() not in ('', '0', 'false', 'no')
    return False


# SNS signing certificates and SubscribeURLs are served from sns.<region>.amazonaws.com
# (sns.<region>.amazonaws.com.cn in China). Other *.amazonaws.com hosts, such as S3
# buckets, can serve anyone's content, so a suffix match on amazonaws.com is not enough.
SNS_HOST_RE = re.compile(r'^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$')

# Seconds to wait for SNS when downloading a signing certificate or confirming a subscription.
SNS_REQUEST_TIMEOUT = 10

# Seconds a downloaded signing certificate is cached, keyed by its URL.
SNS_CERT_CACHE_TIMEOUT = 60 * 60 * 24

# Hash used for each SNS SignatureVersion.
SNS_SIGNATURE_HASHES = {
    '1': hashes.SHA1,
    '2': hashes.SHA256,
}

_warned_no_topic_arns = False


def is_sns_url(url):
    """
    Returns True if `url` is an https URL on an SNS host (sns.<region>.amazonaws.com).
    URLs with a username/password part are rejected.
    """
    if not isinstance(url, str):
        return False
    try:
        url_obj = urlparse(url)
        host = url_obj.hostname
    except ValueError:
        return False
    if url_obj.scheme != 'https' or not host or url_obj.username or url_obj.password:
        return False
    return bool(SNS_HOST_RE.match(host))


def is_allowed_topic(notification):
    """
    Returns True if the SNS message's TopicArn is in BOUNCE_TOPIC_ARNS, or if no
    topics are configured (any topic is accepted, with a one-time warning).
    Checked separately from the signature: a valid signature only proves that some
    SNS topic sent the message, and anyone can create one.
    """
    global _warned_no_topic_arns
    topic_arns = settings.BOUNCE_TOPIC_ARNS
    if not topic_arns:
        if not _warned_no_topic_arns:
            logger.warning(
                "AWS_SES_BOUNCE_TOPIC_ARNS is not set: SNS messages from any topic are accepted. "
                "Set it to your SNS topic ARNs."
            )
            _warned_no_topic_arns = True
        return True
    topic_arn = notification.get('TopicArn')
    if topic_arn not in topic_arns:
        logger.warning("SNS message from unexpected TopicArn: %s", topic_arn)
        return False
    return True


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
            # Pick the hash for the message's SignatureVersion
            signature_version = str(self._data.get('SignatureVersion', '1'))
            hash_class = SNS_SIGNATURE_HASHES.get(signature_version)
            if hash_class is None:
                logger.warning("Unsupported SNS SignatureVersion: %s", signature_version)
                self._verified = False
                return self._verified

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
                    hash_class()  # SignatureVersion 1 is SHA1, 2 is SHA256
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

            # Use the cached certificate if there is one; SNS signing certs rarely change
            cache_key = 'django_aws_ses_sns_cert:' + hashlib.sha256(cert_url.encode('utf-8')).hexdigest()
            pem = cache.get(cache_key)
            cached = pem is not None

            # Fetch the certificate
            if not cached:
                try:
                    response = requests.get(cert_url, timeout=SNS_REQUEST_TIMEOUT)
                except requests.RequestException as e:
                    logger.warning("Failed to download certificate from %s: %s", cert_url, e)
                    return None
                if response.status_code != 200:
                    logger.warning("Failed to download certificate from %s: %s", cert_url, response.status_code)
                    return None
                pem = response.content

            # Load the certificate
            try:
                self._certificate = x509.load_pem_x509_certificate(pem, default_backend())
            except Exception as e:
                logger.warning("Failed to load certificate from %s: %s", cert_url, e)
                return None

            if not cached:
                cache.set(cache_key, pem, SNS_CERT_CACHE_TIMEOUT)

        return self._certificate

    def _get_cert_url(self):
        """
        Retrieves the certificate URL from the message, ensuring it comes from a trusted domain.
        Returns None if the URL is untrusted or invalid.
        """
        cert_url = self._data.get('SigningCertURL')
        url_obj = urlparse(cert_url) if is_sns_url(cert_url) else None
        # Real SNS certificate URLs have no query string or fragment. Rejecting them keeps
        # the certificate cache (keyed by URL) from being bypassed with ?n=1, ?n=2, ...
        if url_obj and url_obj.path.endswith('.pem') and not (url_obj.params or url_obj.query or url_obj.fragment):
            # BOUNCE_CERT_DOMAINS can narrow the SNS hosts trusted, but never widen them
            host_parts = url_obj.hostname.split('.')
            for trusted_domain in settings.BOUNCE_CERT_DOMAINS:
                parts = trusted_domain.split('.')
                if host_parts[-len(parts):] == parts:
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

def filter_recipients(recipiant_list, skip_unsubscribe=False):
    """
    Filters a list of recipient email addresses to exclude invalid or blacklisted emails.
    skip_unsubscribe=True (transactional messages) skips only the unsubscribe filter;
    complaint, bounce and domain filters still apply.
    """
    logger.info("Starting filter_recipients: %s", recipiant_list)

    # Ensure recipient_list is a list
    if not isinstance(recipiant_list, list):
        logger.info("Converting recipients to list")
        recipiant_list = [recipiant_list]

    if recipiant_list:
        if skip_unsubscribe:
            logger.info("Transactional message: skipping unsubscribe filter")
        else:
            recipiant_list = filter_recipients_with_unsubscribe(recipiant_list)
        recipiant_list = filter_recipients_with_complaint_records(recipiant_list)
        recipiant_list = filter_recipients_with_bounce_records(recipiant_list)
        recipiant_list = filter_recipients_with_validater_email_domain(recipiant_list)

    logger.info("Filtered recipient list: %s", recipiant_list)
    return recipiant_list

def filter_recipients_with_unsubscribe(recipiant_list):
    """
    Removes recipients who have unsubscribed (case-insensitive). EmailUnsubscribe
    records are also checked when AWS_SES_FILTER_EMAIL_UNSUBSCRIBES is True, and
    always when AWS_SES_AUTO_LIST_UNSUBSCRIBE is True: the backend issues one-click
    headers for EmailUnsubscribe records, so it must honour them.
    """
    normalized = _normalized_addresses(recipiant_list)
    email_field = User.get_email_field_name()
    blacklist_emails = set(
        User.objects.annotate(aws_ses_addr=Lower(email_field))
        .filter(aws_ses__unsubscribe=True, aws_ses_addr__in=normalized)
        .values_list('aws_ses_addr', flat=True)
    )
    if settings.AWS_SES_FILTER_EMAIL_UNSUBSCRIBES or settings.AWS_SES_AUTO_LIST_UNSUBSCRIBE:
        blacklist_emails.update(
            EmailUnsubscribe.objects.annotate(aws_ses_addr=Lower('email'))
            .filter(unsubscribed=True, aws_ses_addr__in=normalized)
            .values_list('aws_ses_addr', flat=True)
        )
    if blacklist_emails:
        logger.info("Removing unsubscribed recipients: %s", sorted(blacklist_emails))
    return filter_recipients_with_blacklist(recipiant_list, blacklist_emails) if blacklist_emails else recipiant_list

def filter_recipients_with_complaint_records(recipiant_list):
    """
    Removes recipients with complaint records (case-insensitive).
    """
    normalized = _normalized_addresses(recipiant_list)
    blacklist_emails = set(
        ComplaintRecord.objects.annotate(aws_ses_addr=Lower('email'))
        .filter(aws_ses_addr__in=normalized)
        .values_list('aws_ses_addr', flat=True)
    )
    return filter_recipients_with_blacklist(recipiant_list, blacklist_emails) if blacklist_emails else recipiant_list

def filter_recipients_with_bounce_records(recipiant_list):
    """
    Removes recipients with bounce records exceeding SES_BOUNCE_LIMIT.
    Bounces are counted per address (case-insensitive).
    """
    normalized = _normalized_addresses(recipiant_list)
    blacklist_emails = set(
        BounceRecord.objects.annotate(aws_ses_addr=Lower('email'))
        .filter(aws_ses_addr__in=normalized)
        .values('aws_ses_addr')
        .annotate(total=Count('id'))
        .filter(total__gte=settings.SES_BOUNCE_LIMIT)
        .values_list('aws_ses_addr', flat=True)
    )
    return filter_recipients_with_blacklist(recipiant_list, blacklist_emails) if blacklist_emails else recipiant_list

def filter_recipients_with_blacklist(recipiant_list, blacklist_emails):
    """
    Filters out emails from a blacklist. Comparison ignores case and display names;
    the recipient strings that remain are returned unchanged.
    """
    blacklist = {normalize_address(e) for e in blacklist_emails}
    return [email for email in recipiant_list if normalize_address(email) not in blacklist]

def filter_recipients_with_validater_email_domain(recipiant_list):
    """
    Validates email domains for new recipients.
    """
    normalized = _normalized_addresses(recipiant_list)
    sent_list = set(
        SendRecord.objects.annotate(aws_ses_addr=Lower('destination'))
        .filter(aws_ses_addr__in=normalized)
        .values_list('aws_ses_addr', flat=True)
    )
    test_list = [e for e in recipiant_list if normalize_address(e) not in sent_list]

    for e in test_list:
        if not validater_email_domain(e):
            recipiant_list.remove(e)

    return recipiant_list

def validater_email_domain(email):
    """
    Checks if an email's domain has valid MX records and is not blacklisted.
    Accepts "Name <user@example.com>" recipient strings.
    """
    email = normalize_address(email)
    if email.find("@") < 1:
        return False
    domain = email.split("@")[-1]

    if BlackListedDomains.objects.filter(domain__iexact=domain).exists():
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
    if BounceRecord.objects.filter(email__iexact=email).count() >= settings.SES_BOUNCE_LIMIT:
        return False
    if ComplaintRecord.objects.filter(email__iexact=email).exists():
        return False
    return validater_email_domain(email)