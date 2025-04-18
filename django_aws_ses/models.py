import hashlib
import hmac
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

User = get_user_model()
logger = logging.getLogger(__name__)


@receiver(post_save, sender=Site)
def update_awsses_settings(sender, instance, created, **kwargs):
    """Create or update AwsSesSettings when a Site is saved."""
    try:
        if created:
            AwsSesSettings.objects.create(site=instance)
        instance.awssessettings.save()
    except Exception as e:
        logger.error(f"Failed to save AwsSesSettings for site {instance.id}: {e}")


@receiver(post_save, sender=User)
def update_awsses_user(sender, instance, created, **kwargs):
    """Create or update AwsSesUserAddon when a User is saved."""
    try:
        if created:
            AwsSesUserAddon.objects.create(user=instance)
        instance.aws_ses.save()
    except Exception as e:
        logger.error(f"Failed to save AwsSesUserAddon for user {instance.id}: {e}")


class AwsSesSettings(models.Model):
    """AWS SES configuration settings for a site."""
    site = models.OneToOneField(Site, on_delete=models.CASCADE, related_name='awssessettings')
    access_key = models.CharField(max_length=255, blank=True, null=True)
    secret_key = models.CharField(max_length=255, blank=True, null=True)
    region_name = models.CharField(max_length=255, blank=True, null=True)
    region_endpoint = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        verbose_name = 'AWS SES Settings'
        verbose_name_plural = 'AWS SES Settings'

    def __str__(self):
        return f"AWS SES Settings for {self.site.domain}"


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

    def unsubscribe_hash_generator(self):
        """Generate a secure hash for unsubscribe verification."""
        email = self.get_email()
        message = f"{self.user.pk}{email}".encode()
        return hmac.new(
            settings.SECRET_KEY.encode(),
            message,
            hashlib.sha256
        ).hexdigest()

    def check_unsubscribe_hash(self, hash_value):
        """Verify an unsubscribe hash."""
        return hmac.compare_digest(self.unsubscribe_hash_generator(), hash_value)

    def unsubscribe_url_generator(self):
        """Generate a secure unsubscribe URL."""
        uuid = urlsafe_base64_encode(force_bytes(str(self.user.pk)))
        hash_value = self.unsubscribe_hash_generator()
        return reverse('django_aws_ses:aws_ses_unsubscribe', kwargs={"uuid": uuid, "hash": hash_value})


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


class BlackListedDomains(models.Model):
    """Domains blacklisted for email sending."""
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = 'Blacklisted Domain'
        verbose_name_plural = 'Blacklisted Domains'

    def __str__(self):
        return f"Blacklisted: {self.domain} ({self.timestamp})"