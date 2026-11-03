import logging

from django.contrib.auth import get_user_model
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

User = get_user_model()
logger = logging.getLogger(__name__)

@receiver(post_save, sender=User, dispatch_uid="update_awsses_user")
def update_awsses_user(sender, instance, created, **kwargs):
    """Create or update AwsSesUserAddon when a User is saved."""
    try:
        if created:
            AwsSesUserAddon.objects.create(user=instance)
        instance.aws_ses.save()
    except Exception as e:
        logger.error(f"Failed to save AwsSesUserAddon for user {instance.id}: {e}")

class AwsSesUserAddon(models.Model):
    """Additional AWS SES data for a user, including unsubscribe status."""
    user = models.OneToOneField(User, related_name='aws_ses', on_delete=models.CASCADE)
    unsubscribe = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'AWS SES User Addon'
        verbose_name_plural = 'AWS SES User Addons'

    def __str__(self):
        return f"AWS SES Addon for {self.user.email}"

    def get_email(self):
        """Get the user's email address."""
        email_field = self.user.get_email_field_name()
        return getattr(self.user, email_field, '') or ''

    def generate_unsubscribe_token(self):
        """Generate a signed token for unsubscribe verification.

        The token carries only the user's primary key, never the email address.
        """
        from . import unsubscribe
        return unsubscribe.make_token(unsubscribe.KIND_USER, self.user.pk)

    def verify_unsubscribe_token(self, token):
        """Verify a signed unsubscribe token.

        Accepts the current format and, unless AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS
        is False, the "<pk>:<email>" format issued by django_aws_ses <= 0.1.6.

        Args:
            token (str): The signed token to verify.

        Returns:
            bool: True if the token is valid, False otherwise.
        """
        from . import unsubscribe
        loaded = unsubscribe.load_token(token)
        if loaded:
            return loaded == (unsubscribe.KIND_USER, str(self.user.pk))
        legacy = unsubscribe.load_legacy_token(token)
        if not legacy:
            return False
        kind, pk, email = legacy
        return kind == unsubscribe.KIND_USER and str(self.user.pk) == pk and self.get_email() == email

    def unsubscribe_url_generator(self):
        """Generate a secure unsubscribe URL with a signed token.

        Returns AWS_SES_UNSUBSCRIBE_URL when configured, otherwise the library's
        token confirmation page (relative path).
        """
        from . import unsubscribe
        return unsubscribe.build_unsubscribe_url(self.generate_unsubscribe_token())

    def list_unsubscribe_headers(self):
        """Return RFC 8058 List-Unsubscribe / List-Unsubscribe-Post headers for this user."""
        from . import unsubscribe
        return unsubscribe.list_unsubscribe_headers(self)

class SESStat(models.Model):
    """Daily statistics for AWS SES email sending."""
    date = models.DateField(unique=True, db_index=True)
    delivery_attempts = models.PositiveIntegerField()
    bounces = models.PositiveIntegerField()
    complaints = models.PositiveIntegerField()
    rejects = models.PositiveIntegerField()

    class Meta:
        verbose_name = 'SES Statistic'
        verbose_name_plural = 'SES Statistics'
        ordering = ['-date']

    def __str__(self):
        return self.date.strftime("%Y-%m-%d")

class BounceRecord(models.Model):
    """Record of an email bounce event from AWS SES."""
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    email = models.EmailField(db_index=True)
    bounce_type = models.CharField(max_length=255, blank=True, null=True)
    bounce_sub_type = models.CharField(max_length=255, blank=True, null=True)
    reporting_mta = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=255, blank=True, null=True)
    action = models.CharField(max_length=255, blank=True, null=True)
    feedback_id = models.TextField(blank=True, null=True)
    diagnostic_code = models.CharField(max_length=2048, blank=True, null=True)
    cleared = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Bounce Record'
        verbose_name_plural = 'Bounce Records'
        indexes = [models.Index(fields=['email', 'timestamp'])]

    def __str__(self):
        return f"Bounce: {self.email} ({self.bounce_type}, {self.timestamp})"

class ComplaintRecord(models.Model):
    """Record of an email complaint event from AWS SES."""
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    email = models.EmailField(db_index=True)
    sub_type = models.CharField(max_length=255, blank=True, null=True)
    feedback_id = models.TextField(blank=True, null=True)
    feedback_type = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        verbose_name = 'Complaint Record'
        verbose_name_plural = 'Complaint Records'
        indexes = [models.Index(fields=['email', 'timestamp'])]

    def __str__(self):
        return f"Complaint: {self.email} ({self.feedback_type}, {self.timestamp})"

class SendRecord(models.Model):
    """Record of an email send or delivery event from AWS SES."""
    SEND = 'Send'
    DELIVERED = 'Delivery'
    STATUS_CHOICES = (
        (SEND, 'Send'),
        (DELIVERED, 'Delivery'),
    )

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    source = models.EmailField()
    destination = models.EmailField(db_index=True)
    subject = models.TextField(max_length=998, blank=True, null=True)
    message_id = models.TextField(max_length=255, blank=True, null=True)
    aws_process_time = models.IntegerField(default=0)
    smtp_response = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, blank=True, null=True)

    class Meta:
        verbose_name = 'Send Record'
        verbose_name_plural = 'Send Records'
        indexes = [models.Index(fields=['destination', 'timestamp'])]

    def __str__(self):
        return f"Send: {self.source} to {self.destination} ({self.status}, {self.timestamp})"

class UnknownRecord(models.Model):
    """Record of unrecognized AWS SES events."""
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    event_type = models.CharField(max_length=255, blank=True, null=True)
    aws_data = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = 'Unknown Record'
        verbose_name_plural = 'Unknown Records'
        indexes = [models.Index(fields=['event_type', 'timestamp'])]

    def __str__(self):
        return f"Unknown Event: {self.event_type} ({self.timestamp})"

class EmailUnsubscribe(models.Model):
    """Unsubscribe record for non-user email addresses (e.g. mailing list signups)."""
    email = models.EmailField(unique=True, db_index=True)
    unsubscribed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Email Unsubscribe'
        verbose_name_plural = 'Email Unsubscribes'

    def __str__(self):
        return f"{'Unsubscribed' if self.unsubscribed else 'Subscribed'}: {self.email}"

    def generate_token(self):
        """Generate a signed token for unsubscribe verification.

        The token carries only this record's primary key, never the email address.
        """
        from . import unsubscribe
        return unsubscribe.make_token(unsubscribe.KIND_EMAIL, self.pk)

    def verify_token(self, token):
        """Verify a signed unsubscribe token.

        Accepts the current format and, unless AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS
        is False, the signed-email format issued by django_aws_ses <= 0.1.6.
        """
        from . import unsubscribe
        loaded = unsubscribe.load_token(token)
        if loaded:
            return loaded == (unsubscribe.KIND_EMAIL, str(self.pk))
        legacy = unsubscribe.load_legacy_token(token)
        return bool(legacy) and legacy[0] == unsubscribe.KIND_EMAIL and legacy[2] == self.email

    def unsubscribe_url_generator(self):
        """Generate a secure unsubscribe URL with a signed token.

        Returns AWS_SES_UNSUBSCRIBE_URL when configured, otherwise the library's
        token confirmation page (relative path). The address is not in the URL.
        """
        from . import unsubscribe
        return unsubscribe.build_unsubscribe_url(self.generate_token())

    def list_unsubscribe_headers(self):
        """Return RFC 8058 List-Unsubscribe / List-Unsubscribe-Post headers for this address."""
        from . import unsubscribe
        return unsubscribe.list_unsubscribe_headers(self)


class BlackListedDomains(models.Model):
    """Domains blacklisted for email sending."""
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = 'Blacklisted Domain'
        verbose_name_plural = 'Blacklisted Domains'

    def __str__(self):
        return f"Blacklisted: {self.domain} ({self.timestamp})"