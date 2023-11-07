import hashlib
import logging
import traceback

from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.sites.models import Site
from django.contrib.auth import get_user_model # If used custom user model
from django.urls import reverse
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

User = get_user_model()

class AwsSesSettings(models.Model):
    site = models.OneToOneField(Site, on_delete=models.CASCADE)
    access_key = models.CharField(max_length=255, blank=True, null=True,)
    secret_key = models.CharField(max_length=255, blank=True, null=True,)
    region_name = models.CharField(max_length=255, blank=True, null=True,)
    region_endpoint = models.CharField(max_length=255, blank=True, null=True,)
    
    class Meta:
        verbose_name = 'AWS SES Settings'
    
@receiver(post_save, sender=Site)
def update_awsses_settings(sender, instance, created, **kwargs):
    try:
        if created:
            AwsSesSettings.objects.create(site=instance)
        instance.awssessettings.save()
    except Exception as e:
        print("Exception saving site error:%s" % e)    
        track = traceback.format_exc()
        print("Exception saving site track: %s" % (track))    
        
    
class AwsSesUserAddon(models.Model):
    user = models.OneToOneField(User, related_name='aws_ses', on_delete=models.CASCADE)
    unsubscribe = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = 'User Data'
    
    def get_email(self):
        email_field = self.user.get_email_field_name()
        email = getattr(self, email_field, '') or ''
        return email
        
    def unsubscribe_hash_generator(self):
        email = self.get_email()
        string_to_hash = "%s%s" % (str(self.user.pk), email)
        return hashlib.md5(string_to_hash.encode()).hexdigest()
    
    def check_unsubscribe_hash(self, hash):
        test_hash = self.unsubscribe_hash_generator()
        return hash == test_hash
    
    def unsubscribe_url_generator(self):
        uuid = urlsafe_base64_encode(force_bytes(self.user.pk))
        hash = self.unsubscribe_hash_generator()
        return reverse('django_aws_ses:aws_ses_unsubscribe', kwargs={"uuid":uuid, "hash":hash})

@receiver(post_save, sender=User)
def update_awsses_user(sender, instance, created, **kwargs):
    if created:
        AwsSesUserAddon.objects.create(user=instance)
    try:
        instance.aws_ses.save()
    except AwsSesUserAddon.DoesNotExist:
        AwsSesUserAddon.objects.create(user=instance)

class SESStat(models.Model):
    date = models.DateField(unique=True, db_index=True)
    delivery_attempts = models.PositiveIntegerField()
    bounces = models.PositiveIntegerField()
    complaints = models.PositiveIntegerField()
    rejects = models.PositiveIntegerField()
 
    class Meta:
        verbose_name = 'SES Stat'
        ordering = ['-date']
 
    def __unicode__(self):
        return self.date.strftime("%Y-%m-%d")
 
class BounceRecord(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    email = models.EmailField()
    bounce_type = models.CharField(max_length=255, blank=True, null=True,)
    bounce_sub_type = models.CharField(max_length=255, blank=True, null=True,)
    reporting_mta = models.CharField(max_length=255, blank=True, null=True,)
    status = models.CharField(max_length=255, blank=True, null=True,)
    action = models.CharField(max_length=255, blank=True, null=True,)
    feedback_id = models.TextField(max_length=255, blank=True, null=True,)
    diagnostic_code = models.CharField(max_length=2048, blank=True, null=True,)
    cleared = models.BooleanField(default=False)
    
    class Meta:
        indexes = [models.Index(fields=["email"]),]
    
    def __str__(self):
        return "email: %s, type: %s, sub_type: %s, status: %s, date: %s" % (self.email, self.bounce_type, self.bounce_sub_type, self.status, self.timestamp)
    
class ComplaintRecord(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    email = models.EmailField()
    sub_type = models.CharField(max_length=255, blank=True, null=True,)
    feedback_id = models.TextField(max_length=255, blank=True, null=True,)
    feedback_type = models.CharField(max_length=255, blank=True, null=True,)
     
    def __str__(self):
        return "email: %s, sub_type: %s, feedback_type: %s, date: %s" % (self.email, self.bounce_sub_type, self.feedback_type, self.timestamp)

class SendRecord(models.Model):

    SEND = 'Send'
    DELIVERED = 'Delivery'
    STATUS_CHOICE = (
        (SEND, SEND),
        (DELIVERED, DELIVERED),
    )
    
    timestamp = models.DateTimeField(auto_now_add=True)
    source = models.EmailField()
    destination = models.EmailField()
    subject = models.TextField(max_length=255, blank=True, null=True,)
    message_id = models.TextField(max_length=255, blank=True, null=True,)
    aws_process_time = models.IntegerField()
    smtp_response = models.CharField(max_length=255, blank=True, null=True,)
    status = models.CharField(max_length=255, blank=True, null=True,)
    
    class Meta:
        indexes = [models.Index(fields=["destination"]),]
     
    def __str__(self):
        return "source: %s, destination: %s, subject: %s, date: %s" % (self.source, self.destination, self.subject, self.timestamp)

    
class UnknownRecord(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=255, blank=True, null=True,)
    aws_data = models.TextField(blank=True, null=True,)
     
    def __str__(self):
        return "eventType: %s, timestamp: %s" % (self.eventType, self.timestamp)
     
class BlackListedDomains(models.Model):
    domain = models.CharField(max_length=255, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return "%s, blocked: %s" % (self.domain, self.timestamp)