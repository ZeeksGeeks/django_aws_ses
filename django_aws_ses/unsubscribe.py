"""Unsubscribe tokens, URLs, RFC 8058 one-click headers and a JSON-friendly API.

Tokens carry only the record kind and id, never the email address, and are signed
with a dedicated salt. Tokens issued by django_aws_ses <= 0.1.6 (a plain ``Signer``
signature over the email address) are still accepted unless
``AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS`` is False.

The helpers here are framework-neutral so apps can build their own (e.g. DRF)
endpoints on top of them:

    record = resolve_token(token)          # AwsSesUserAddon | EmailUnsubscribe | None
    get_status(record)                     # {'kind': ..., 'unsubscribed': ..., 'email': masked}
    set_unsubscribed(record, True/False)
"""
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.urls import reverse

from . import settings
from . import utils
from .models import AwsSesUserAddon, EmailUnsubscribe

logger = settings.logger
User = get_user_model()

TOKEN_SALT = 'django_aws_ses.unsubscribe'
KIND_USER = 'user'
KIND_EMAIL = 'email'
LIST_UNSUBSCRIBE_HEADERS = ('List-Unsubscribe', 'List-Unsubscribe-Post')
ONE_CLICK_POST_VALUE = 'List-Unsubscribe=One-Click'


def make_token(kind, pk):
    """Sign a token that identifies a record by kind and primary key only."""
    return signing.dumps({'kind': kind, 'id': str(pk)}, salt=TOKEN_SALT)


def load_token(token):
    """Return ``(kind, id)`` for a valid current-format token, otherwise None."""
    try:
        data = signing.loads(token, salt=TOKEN_SALT)
    except (signing.BadSignature, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    kind, pk = data.get('kind'), data.get('id')
    if kind not in (KIND_USER, KIND_EMAIL) or not isinstance(pk, str) or not pk:
        return None
    return kind, pk


def load_legacy_token(token):
    """Decode a token issued by django_aws_ses <= 0.1.6.

    Returns ``('user', pk, email)``, ``('email', None, email)`` or None. Always None
    when ``AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS`` is False.
    """
    if not settings.AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS:
        return None
    try:
        value = signing.Signer().unsign(token)
    except signing.BadSignature:
        return None
    if ':' in value:
        # AwsSesUserAddon tokens signed "<pk>:<email>"
        pk, _, email = value.partition(':')
        return KIND_USER, pk, email
    # EmailUnsubscribe tokens signed the bare email address
    return KIND_EMAIL, None, value


def _addon_for_user(user):
    """Return the user's AwsSesUserAddon, creating it if missing (as the existing views do)."""
    try:
        return user.aws_ses
    except AwsSesUserAddon.DoesNotExist:
        return AwsSesUserAddon.objects.create(user=user)


def _addon_for_user_pk(pk):
    try:
        user = User.objects.get(pk=pk)
    except (User.DoesNotExist, ValueError, TypeError, ValidationError):
        return None
    return _addon_for_user(user)


def resolve_token(token):
    """Return the AwsSesUserAddon or EmailUnsubscribe a token refers to, or None."""
    loaded = load_token(token)
    if loaded:
        kind, pk = loaded
        if kind == KIND_USER:
            return _addon_for_user_pk(pk)
        try:
            return EmailUnsubscribe.objects.get(pk=pk)
        except (EmailUnsubscribe.DoesNotExist, ValueError, TypeError, ValidationError):
            return None

    legacy = load_legacy_token(token)
    if legacy:
        kind, pk, email = legacy
        if kind == KIND_USER:
            addon = _addon_for_user_pk(pk)
            # Legacy user tokens are only valid while the address still matches.
            return addon if addon is not None and addon.get_email() == email else None
        return EmailUnsubscribe.objects.filter(email=email).first()
    return None


def as_record(obj):
    """Accept a User, AwsSesUserAddon or EmailUnsubscribe and return the unsubscribe record."""
    if isinstance(obj, (AwsSesUserAddon, EmailUnsubscribe)):
        return obj
    if isinstance(obj, User):
        return _addon_for_user(obj)
    raise TypeError(f"Expected User, AwsSesUserAddon or EmailUnsubscribe, got {type(obj).__name__}")


def token_for(obj):
    """Return a current-format unsubscribe token for a User, AwsSesUserAddon or EmailUnsubscribe."""
    record = as_record(obj)
    if isinstance(record, AwsSesUserAddon):
        return record.generate_unsubscribe_token()
    return record.generate_token()


def build_unsubscribe_url(token):
    """Return the URL of the page where a person manages their subscription.

    Uses ``AWS_SES_UNSUBSCRIBE_URL`` (format string with ``{token}`` or a callable
    taking the token) when set, otherwise the library's token confirmation page
    (a relative path, as the generators have always returned).
    """
    target = settings.AWS_SES_UNSUBSCRIBE_URL
    if callable(target):
        return target(token)
    if target:
        return target.format(token=token)
    return reverse('django_aws_ses:aws_ses_unsubscribe_token', kwargs={'token': token})


def one_click_url(token):
    """Return the absolute RFC 8058 one-click URL for a token.

    Raises:
        ImproperlyConfigured: If ``AWS_SES_UNSUBSCRIBE_BASE_URL`` is not set.
    """
    base = settings.AWS_SES_UNSUBSCRIBE_BASE_URL
    if not base:
        raise ImproperlyConfigured(
            "AWS_SES_UNSUBSCRIBE_BASE_URL must be set (e.g. 'https://api.example.com') "
            "to build one-click List-Unsubscribe URLs."
        )
    if not base.startswith('https://'):
        logger.warning("AWS_SES_UNSUBSCRIBE_BASE_URL is not https; RFC 8058 requires an HTTPS URI")
    return base.rstrip('/') + reverse('django_aws_ses:aws_ses_one_click_unsubscribe', kwargs={'token': token})


def list_unsubscribe_headers(obj):
    """Return RFC 8058 one-click headers for a User, AwsSesUserAddon or EmailUnsubscribe.

    Example:
        EmailMessage(..., headers=list_unsubscribe_headers(user))
    """
    return {
        'List-Unsubscribe': f"<{one_click_url(token_for(obj))}>",
        'List-Unsubscribe-Post': ONE_CLICK_POST_VALUE,
    }


def record_for_address(address):
    """Map a recipient address to an unsubscribe record, or None.

    A single user whose email matches (case-insensitively) wins; otherwise an
    EmailUnsubscribe record with that address. Display names are ignored.
    """
    address = utils.normalize_address(address)
    if not address:
        return None
    email_field = User.get_email_field_name()
    users = list(User.objects.filter(**{f'{email_field}__iexact': address})[:2])
    if len(users) == 1:
        return _addon_for_user(users[0])
    return EmailUnsubscribe.objects.filter(email__iexact=address).first()


def apply_auto_list_unsubscribe(mime_message, recipients):
    """Add one-click headers to a built MIME message when it has exactly one mappable recipient.

    Tokens are per recipient, so multi-recipient messages are left alone, as are
    messages that already carry List-Unsubscribe headers.

    Returns:
        bool: True if headers were added.
    """
    if len(recipients) != 1:
        return False
    if any(header in mime_message for header in LIST_UNSUBSCRIBE_HEADERS):
        return False
    record = record_for_address(recipients[0])
    if record is None:
        return False
    for name, value in list_unsubscribe_headers(record).items():
        mime_message[name] = value
    return True


def get_email(obj):
    """Return the email address an unsubscribe record belongs to."""
    record = as_record(obj)
    if isinstance(record, AwsSesUserAddon):
        return record.get_email()
    return record.email


def is_unsubscribed(obj):
    record = as_record(obj)
    if isinstance(record, AwsSesUserAddon):
        return record.unsubscribe
    return record.unsubscribed


def set_unsubscribed(obj, value):
    """Set the unsubscribe state of a record and save it."""
    record = as_record(obj)
    if isinstance(record, AwsSesUserAddon):
        record.unsubscribe = bool(value)
        record.save(update_fields=['unsubscribe'])
    else:
        record.unsubscribed = bool(value)
        record.save(update_fields=['unsubscribed'])
    logger.info(
        f"{'Unsubscribed' if value else 'Re-subscribed'} {type(record).__name__} pk={record.pk}"
    )
    return record


def mask_email(email):
    """Mask an address for display to whoever holds a link, e.g. 't***@example.com'."""
    local, sep, domain = (email or '').partition('@')
    if not sep:
        return '***'
    return f"{local[:1]}***@{domain}"


def get_status(obj):
    """Return a JSON-serialisable status dict for a record."""
    record = as_record(obj)
    return {
        'kind': KIND_USER if isinstance(record, AwsSesUserAddon) else KIND_EMAIL,
        'unsubscribed': is_unsubscribed(record),
        'email': mask_email(get_email(record)),
    }
