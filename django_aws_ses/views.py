import json
import logging
from datetime import datetime

import boto3
import pytz
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.http import require_POST
from django.views.generic.base import TemplateView
from django.core.signing import Signer, BadSignature

from . import settings
from . import signals
from . import utils
from .models import BounceRecord, ComplaintRecord, SendRecord, UnknownRecord, AwsSesUserAddon

logger = settings.logger
User = get_user_model()


def superuser_only(view_func):
    """Decorator to restrict a view to superusers only."""
    def _inner(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    return _inner


def stats_to_list(stats_dict, localize=pytz):
    """Parse SES send statistics into an ordered list of 15-minute summaries.

    Args:
        stats_dict (dict): Raw SES statistics data.
        localize (module): Timezone module (default: pytz).

    Returns:
        list: Sorted list of datapoints with localized timestamps.
    """
    datapoints = []
    current_tz = localize.timezone(settings.TIME_ZONE) if localize else None

    for dp in stats_dict['SendDataPoints']:
        if current_tz:
            utc_dt = dp['Timestamp']
            dp['Timestamp'] = current_tz.normalize(utc_dt.astimezone(current_tz))
        datapoints.append(dp)

    return sorted(datapoints, key=lambda x: x['Timestamp'])


def emails_parse(emails_dict):
    """Parse SES verified email addresses into a sorted list.

    Args:
        emails_dict (dict): Raw SES verified email data.

    Returns:
        list: Sorted list of verified email addresses.
    """
    return sorted(emails_dict['VerifiedEmailAddresses'])


def sum_stats(stats_data):
    """Summarize SES statistics from a list of datapoints.

    Args:
        stats_data (list): List of SES datapoints.

    Returns:
        dict: Summary of bounces, complaints, delivery attempts, and rejects.
    """
    summary = {
        'Bounces': 0,
        'Complaints': 0,
        'DeliveryAttempts': 0,
        'Rejects': 0,
    }
    for dp in stats_data:
        summary['Bounces'] += dp['Bounces']
        summary['Complaints'] += dp['Complaints']
        summary['DeliveryAttempts'] += dp['DeliveryAttempts']
        summary['Rejects'] += dp['Rejects']
    return summary


@superuser_only
def dashboard(request):
    """Display SES send statistics dashboard for superusers.

    Args:
        request: HTTP request object.

    Returns:
        HttpResponse: Rendered dashboard with SES statistics.
    """
    cache_key = 'django_aws_ses_status'
    cached_view = cache.get(cache_key)
    if cached_view:
        return cached_view

    ses_conn = boto3.client(
        'ses',
        aws_access_key_id=settings.ACCESS_KEY,
        aws_secret_access_key=settings.SECRET_KEY,
        region_name=settings.AWS_SES_REGION_NAME,
        endpoint_url=settings.AWS_SES_REGION_ENDPOINT,
    )

    try:
        quota_dict = ses_conn.get_send_quota()
        verified_emails_dict = ses_conn.list_verified_email_addresses()
        stats = ses_conn.get_send_statistics()
    except Exception as e:
        logger.error(f"Failed to fetch SES statistics: {e}")
        return HttpResponseBadRequest("Failed to fetch SES statistics")

    verified_emails = emails_parse(verified_emails_dict)
    ordered_data = stats_to_list(stats)
    summary = sum_stats(ordered_data)

    context = {
        'title': 'SES Statistics',
        'datapoints': ordered_data,
        '24hour_quota': quota_dict['Max24HourSend'],
        '24hour_sent': quota_dict['SentLast24Hours'],
        '24hour_remaining': quota_dict['Max24HourSend'] - quota_dict['SentLast24Hours'],
        'persecond_rate': quota_dict['MaxSendRate'],
        'verified_emails': verified_emails,
        'summary': summary,
        'local_time': True,
    }

    response = render(request, 'django_aws_ses/send_stats.html', context)
    cache.set(cache_key, response, 60 * 15)  # Cache for 15 minutes
    return response


@require_POST
def handle_bounce(request):
    """Handle AWS SES/SNS bounce, complaint, or delivery notifications.

    Args:
        request: HTTP request object with SNS notification JSON.

    Returns:
        HttpResponse: HTTP 200 for successful processing, 400 for invalid JSON.
    """
    logger.info("Received SNS callback")

    try:
        notification = json.loads(request.body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as e:
        logger.warning(f"Invalid SNS notification JSON: {e}")
        return HttpResponseBadRequest("Invalid JSON")

    if settings.VERIFY_BOUNCE_SIGNATURES and not utils.verify_bounce_message(notification):
        logger.warning(f"Unverified SNS notification: Type={notification.get('Type')}")
        return HttpResponse()

    notification_type = notification.get('Type')
    if notification_type in ('SubscriptionConfirmation', 'UnsubscribeConfirmation'):
        logger.info(f"Received {notification_type}: TopicArn={notification.get('TopicArn')}")
        subscribe_url = notification.get('SubscribeURL')
        if subscribe_url:
            try:
                import requests
                response = requests.get(subscribe_url)
                response.raise_for_status()
            except requests.RequestException as e:
                logger.error(f"Failed to confirm {notification_type}: {e}")
        return HttpResponse()

    if notification_type != 'Notification':
        UnknownRecord.objects.create(event_type=notification_type, aws_data=str(notification))
        logger.info(f"Received unknown notification type: {notification_type}")
        return HttpResponse()

    try:
        message = json.loads(notification['Message'])
    except ValueError as e:
        logger.warning(f"Invalid message JSON in notification: {e}")
        return HttpResponse()

    mail_obj = message.get('mail', {})
    event_type = message.get('notificationType', message.get('eventType', 'Unknown'))

    if event_type == 'Bounce':
        bounce_obj = message.get('bounce', {})
        feedback_id = bounce_obj.get('feedbackId')
        bounce_type = bounce_obj.get('bounceType')
        bounce_subtype = bounce_obj.get('bounceSubType')
        logger.info(f"Received bounce: feedbackId={feedback_id}, type={bounce_type}, subtype={bounce_subtype}")

        for recipient in bounce_obj.get('bouncedRecipients', []):
            BounceRecord.objects.create(
                email=recipient.get('emailAddress'),
                status=recipient.get('status'),
                action=recipient.get('action'),
                diagnostic_code=recipient.get('diagnosticCode'),
                bounce_type=bounce_type,
                bounce_sub_type=bounce_subtype,
                feedback_id=feedback_id,
                reporting_mta=bounce_obj.get('reportingMTA'),
            )

        signals.bounce_received.send(
            sender=handle_bounce,
            mail_obj=mail_obj,
            bounce_obj=bounce_obj,
            raw_message=request.body,
        )

    elif event_type == 'Complaint':
        complaint_obj = message.get('complaint', {})
        feedback_id = complaint_obj.get('feedbackId')
        feedback_type = complaint_obj.get('complaintFeedbackType')
        logger.info(f"Received complaint: feedbackId={feedback_id}, type={feedback_type}")

        for recipient in complaint_obj.get('complainedRecipients', []):
            ComplaintRecord.objects.create(
                email=recipient.get('emailAddress'),
                sub_type=complaint_obj.get('complaintSubType'),
                feedback_id=feedback_id,
                feedback_type=feedback_type,
            )

        signals.complaint_received.send(
            sender=handle_bounce,
            mail_obj=mail_obj,
            complaint_obj=complaint_obj,
            raw_message=request.body,
        )

    elif event_type in ('Delivery', 'Send'):
        send_obj = mail_obj
        source = send_obj.get('source', settings.DEFAULT_FROM_EMAIL)
        destinations = send_obj.get('destination', [])
        message_id = send_obj.get('messageId', 'N/A')
        delivery = message.get('delivery', {})
        aws_process_time = delivery.get('processingTimeMillis', 0)
        smtp_response = delivery.get('smtpResponse', 'N/A')
        subject = send_obj.get('commonHeaders', {}).get('subject', 'N/A')

        logger.info(f"Received {event_type} notification: messageId={message_id}")

        for destination in destinations:
            try:
                send_record, created = SendRecord.objects.get_or_create(
                    source=source,
                    destination=destination,
                    status=event_type,
                    message_id=message_id,
                    defaults={
                        "aws_process_time": aws_process_time,
                        "smtp_response": smtp_response,
                        "subject": subject,
                    }
                )
                if send_record.subject == "N/A":
                    send_record.subject = subject
                if send_record.smtp_response == "N/A":
                    send_record.smtp_response = smtp_response
                if send_record.aws_process_time == 0:
                    send_record.aws_process_time = aws_process_time
                send_record.save()
            except Exception as e:
                logger.error(f"Failed to save SendRecord for {destination}: {e}")

        signals.delivery_received.send(
            sender=handle_bounce,
            mail_obj=mail_obj,
            delivery_obj=send_obj,
            raw_message=request.body,
        )

    else:
        UnknownRecord.objects.create(event_type=event_type, aws_data=str(notification))
        logger.warning(f"Received unknown event: {event_type}")

    return HttpResponse()


class HandleUnsubscribe(TemplateView):
    """View to handle email unsubscribe and re-subscribe requests with confirmation."""
    http_method_names = ['get', 'post']
    template_name = settings.UNSUBSCRIBE_TEMPLATE
    base_template_name = settings.BASE_TEMPLATE
    confirmation_message = "Please confirm your email subscription preference"
    unsubscribe_message = "You have been unsubscribed"
    resubscribe_message = "You have been re-subscribed"

    def get_context_data(self, **kwargs):
        """Add base template and appropriate message to context."""
        context = super().get_context_data(**kwargs)
        context['base_template_name'] = self.base_template_name
        context['confirmation_message'] = self.confirmation_message
        context['unsubscribe_message'] = self.unsubscribe_message
        context['resubscribe_message'] = self.resubscribe_message
        context['user_email'] = getattr(self, 'user_email', '')
        context['action'] = getattr(self, 'action', '')
        return context

    def get(self, request, *args, **kwargs):
        """Show confirmation page for unsubscribe or re-subscribe."""
        uuid = self.kwargs['uuid']
        token = self.kwargs['token']
        self.action = ''  # Reset action to ensure confirmation page

        try:
            uuid = force_str(urlsafe_base64_decode(uuid))
            user = User.objects.get(pk=uuid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            logger.warning(f"Invalid unsubscribe UUID: {e}")
            return redirect(settings.HOME_URL)

        try:
            ses = user.aws_ses
        except AwsSesUserAddon.DoesNotExist:
            ses = AwsSesUserAddon.objects.create(user=user)

        if not user or not ses.verify_unsubscribe_token(token):
            logger.warning(f"Invalid token for user: {user.email}")
            return redirect(settings.HOME_URL)

        self.user_email = user.email
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        """Process unsubscribe or re-subscribe request."""
        uuid = self.kwargs['uuid']
        token = self.kwargs['token']
        action = request.POST.get('action')

        try:
            uuid = force_str(urlsafe_base64_decode(uuid))
            user = User.objects.get(pk=uuid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            logger.warning(f"Invalid unsubscribe UUID: {e}")
            return redirect(settings.HOME_URL)

        try:
            ses = user.aws_ses
        except AwsSesUserAddon.DoesNotExist:
            ses = AwsSesUserAddon.objects.create(user=user)

        if not user or not ses.verify_unsubscribe_token(token):
            logger.warning(f"Invalid token for user: {user.email}")
            return redirect(settings.HOME_URL)

        self.user_email = user.email
        if action == 'unsubscribe':
            ses.unsubscribe = True
            ses.save()
            logger.info(f"Unsubscribed user: {user.email}")
            self.action = 'unsubscribe'
        elif action == 'resubscribe':
            ses.unsubscribe = False
            ses.save()
            logger.info(f"Re-subscribed user: {user.email}")
            self.action = 'resubscribe'
        else:
            logger.warning(f"Invalid action for user: {user.email}")
            return redirect(settings.HOME_URL)

        return render(request, self.template_name, self.get_context_data())