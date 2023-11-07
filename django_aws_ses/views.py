import json

import boto3
import pytz
try:
    from urllib.request import urlopen
    from urllib.error import URLError
except ImportError:
    from urllib2 import urlopen, URLError
import copy
import logging
from datetime import datetime

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.http import require_POST
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.views.generic.base import TemplateView
from django.utils.encoding import force_bytes, force_text

from . import settings
from . import signals
from . import utils
from .models import (
    BounceRecord,
    ComplaintRecord,
    SendRecord,
    UnknownRecord,
    AwsSesUserAddon
    ) 

logger = settings.logger

User = get_user_model()

def superuser_only(view_func):
    """
    Limit a view to superuser only.
    """
    def _inner(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    return _inner


def stats_to_list(stats_dict, localize=pytz):
    """
    Parse the output of ``SESConnection.get_send_statistics()`` in to an
    ordered list of 15-minute summaries.
    """
    # Make a copy, so we don't change the original stats_dict.
    result = copy.deepcopy(stats_dict)
    datapoints = []
    if localize:
        current_tz = localize.timezone(settings.TIME_ZONE)
    else:
        current_tz = None
    for dp in result['SendDataPoints']:
        if current_tz:
            utc_dt = dp['Timestamp']
            dp['Timestamp'] = current_tz.normalize(
                utc_dt.astimezone(current_tz))
        datapoints.append(dp)

    datapoints.sort(key=lambda x: x['Timestamp'])

    return datapoints


def emails_parse(emails_dict):
    """
    Parse the output of ``SESConnection.list_verified_emails()`` and get
    a list of emails.
    """
    return sorted([email for email in emails_dict['VerifiedEmailAddresses']])


def sum_stats(stats_data):
    """
    Summarize the bounces, complaints, delivery attempts and rejects from a
    list of datapoints.
    """
    t_bounces = 0
    t_complaints = 0
    t_delivery_attempts = 0
    t_rejects = 0
    for dp in stats_data:
        t_bounces += dp['Bounces']
        t_complaints += dp['Complaints']
        t_delivery_attempts += dp['DeliveryAttempts']
        t_rejects += dp['Rejects']

    return {
        'Bounces': t_bounces,
        'Complaints': t_complaints,
        'DeliveryAttempts': t_delivery_attempts,
        'Rejects': t_rejects,
    }


@superuser_only
def dashboard(request):
    """
    Graph SES send statistics over time.
    """
    cache_key = 'vhash:django_aws_ses_status'
    cached_view = cache.get(cache_key)
    if cached_view:
        return cached_view

    ses_conn = boto3.client(
        'ses',
        aws_access_key_id=settings.ACCESS_KEY,
        aws_secret_access_key=settings.SECRET_KEY,
        region_name=settings.AWS_SES_REGION_NAME,
        endpoint_url=settings.AWS_SES_REGION_ENDPOINT_URL,
    )

    quota_dict = ses_conn.get_send_quota()
    verified_emails_dict = ses_conn.list_verified_email_addresses()
    stats = ses_conn.get_send_statistics()

    verified_emails = emails_parse(verified_emails_dict)
    ordered_data = stats_to_list(stats)
    summary = sum_stats(ordered_data)

    extra_context = {
        'title': 'SES Statistics',
        'datapoints': ordered_data,
        '24hour_quota': quota_dict['Max24HourSend'],
        '24hour_sent': quota_dict['SentLast24Hours'],
        '24hour_remaining':
            quota_dict['Max24HourSend'] -
            quota_dict['SentLast24Hours'],
        'persecond_rate': quota_dict['MaxSendRate'],
        'verified_emails': verified_emails,
        'summary': summary,
        'access_key': settings.ACCESS_KEY,
        'local_time': True,
    }

    response = render(request, 'django_aws_ses/send_stats.html', extra_context)

    cache.set(cache_key, response, 60 * 15)  # Cache for 15 minutes
    return response


@require_POST
def handle_bounce(request):
    """
    Handle a bounced email via an SNS webhook.

    Parse the bounced message and send the appropriate signal.
    For bounce messages the bounce_received signal is called.
    For complaint messages the complaint_received signal is called.
    See: http://docs.aws.amazon.com/sns/latest/gsg/json-formats.html#http-subscription-confirmation-json
    See: http://docs.amazonwebservices.com/ses/latest/DeveloperGuide/NotificationsViaSNS.html

    In addition to email bounce requests this endpoint also supports the SNS
    subscription confirmation request. This request is sent to the SNS
    subscription endpoint when the subscription is registered.
    See: http://docs.aws.amazon.com/sns/latest/gsg/Subscribe.html

    For the format of the SNS subscription confirmation request see this URL:
    http://docs.aws.amazon.com/sns/latest/gsg/json-formats.html#http-subscription-confirmation-json

    SNS message signatures are verified by default. This functionality can
    be disabled by setting AWS_SES_VERIFY_BOUNCE_SIGNATURES to False.
    However, this is not recommended.
    See: http://docs.amazonwebservices.com/sns/latest/gsg/SendMessageToHttp.verify.signature.html
    """
    logger.warning(u'Received SNS call back')
    
    
    raw_json = request.body

    try:
        notification = json.loads(raw_json.decode('utf-8'))
    except ValueError as e:
        # TODO: What kind of response should be returned here?
        logger.warning(u'Received bounce with bad JSON: "%s"', e)
        return HttpResponseBadRequest()

    # Verify the authenticity of the bounce message.
    if (settings.VERIFY_BOUNCE_SIGNATURES and
            not utils.verify_bounce_message(notification)):
        # Don't send any info back when the notification is not
        # verified. Simply, don't process it.
        logger.info(
            u'Received unverified notification: Type: %s',
            notification.get('Type'),
            extra={
                'notification': notification,
            },
        )
        return HttpResponse()
    logger.info('notification.get("Type"): %s' % notification.get("Type"))
    if notification.get('Type') in ('SubscriptionConfirmation',
                                    'UnsubscribeConfirmation'):
        # Process the (un)subscription confirmation.

        logger.info(
            u'Received subscription confirmation: TopicArn: %s',
            notification.get('TopicArn'),
            extra={
                'notification': notification,
            },
        )

        # Get the subscribe url and hit the url to confirm the subscription.
        subscribe_url = notification.get('SubscribeURL')
        try:
            urlopen(subscribe_url).read()
        except URLError as e:
            # Some kind of error occurred when confirming the request.
            logger.error(
                u'Could not confirm subscription: "%s"', e,
                extra={
                    'notification': notification,
                },
                exc_info=True,
            )
    elif notification.get('Type') == 'Notification':
        try:
            message = json.loads(notification['Message'])
        except ValueError as e:
            # The message isn't JSON.
            # Just ignore the notification.
            logger.warning(u'Received bounce with bad JSON: "%s"', e, extra={
                'notification': notification,
            })
            
        else:
            
            mail_obj = message.get('mail')
            event_type = message.get('notificationType', message.get('eventType'))
            logger.info('event_type: %s' % event_type)
            if event_type == 'Bounce':
                # Bounce
                bounce_obj = message.get('bounce', {})

                # Logging
                feedback_id = bounce_obj.get('feedbackId')
                bounce_type = bounce_obj.get('bounceType')
                bounce_subtype = bounce_obj.get('bounceSubType')
                bounce_recipients = bounce_obj.get('bouncedRecipients', [])
                logger.info(
                    u'Received bounce notification: feedbackId: %s, bounceType: %s, bounceSubType: %s',
                    feedback_id, bounce_type, bounce_subtype,
                    extra={
                        'notification': notification,
                    },
                )
                
                # create a BounceRecord so we can keep from sending to bad emails.
                logger.info('create records')
                for recipient in bounce_recipients:
                    logger.info('recipient: %s' % recipient)
                    BounceRecord.objects.create(
                        email = recipient.get('emailAddress', None),
                        status = recipient.get('status', None),
                        action = recipient.get('action', None),
                        diagnostic_code = recipient.get('diagnosticCode', None),
                        bounce_type = bounce_obj.get('bounceType', None),
                        bounce_sub_type = bounce_obj.get('bounceSubType', None),
                        feedback_id = bounce_obj.get('feedbackId', None),
                        reporting_mta = bounce_obj.get('reportingMTA', None),
                    )
                

                signals.bounce_received.send(
                    sender=handle_bounce,
                    mail_obj=mail_obj,
                    bounce_obj=bounce_obj,
                    raw_message=raw_json,
                )
                
            elif event_type == 'Complaint':
                # Complaint
                complaint_obj = message.get('complaint', {})

                # Logging
                feedback_id = complaint_obj.get('feedbackId')
                feedback_type = complaint_obj.get('complaintFeedbackType')
                complaint_recipients = complaint_obj.get('complainedRecipients')
                logger.info('create records')
                for recipient in complaint_recipients:
                    logger.info('recipient: %s' % recipient)
                    ComplaintRecord.objects.create(
                        email = recipient.get('emailAddress', None),
                        sub_type = complaint_obj.get('complaintSubType', None),
                        feedback_id = complaint_obj.get('feedbackId', None),
                        feedback_type = complaint_obj.get('complaintFeedbackType', None),
                    )
                
                logger.info(
                    u'Received complaint notification: feedbackId: %s, feedbackType: %s',
                    feedback_id, feedback_type,
                    extra={
                        'notification': notification,
                    },
                )

                signals.complaint_received.send(
                    sender=handle_bounce,
                    mail_obj=mail_obj,
                    complaint_obj=complaint_obj,
                    raw_message=raw_json,
                )
                
            elif event_type in ['Delivery','Send']:
                # Delivery
                send_obj = message.get('mail', {})
                
                logger.info('send_obj: %s' % send_obj)
                
                source = send_obj.get('source', 'N/A')#settings.DEFAULT_FROM_EMAIL)
                destinations = send_obj.get('destination', [])
                message_id = send_obj.get('messageId','N/A')
                delivery = message.get('delivery', None)
                aws_process_time = -1
                smtp_response = 'N/A'
                if delivery:
                    logger.info('we are a delivery and had a delivery key')
                    aws_process_time = delivery.get('processingTimeMillis',0)
                    smtp_response = delivery.get('smtpResponse', 'N/A')
                
                common_headers = send_obj.get('commonHeaders', None)
                subject = "N/A"
                if common_headers:
                    subject = common_headers.get('subject','N/A')
                status = event_type
                logger.info('create records')
                logger.info('destinations: %s' % destinations)
                for destination in destinations:
                    try:
                        logger.info('destination: %s' % destination)
                        send_record, created = SendRecord.objects.get_or_create(
                                source = source,
                                destination = destination,
                                status = status,
                                message_id = message_id,
                                defaults={
                                    "aws_process_time": aws_process_time,
                                    "smtp_response": smtp_response,
                                    "subject": subject
                                    }
                                
                            )
                        if send_record.subject == "N/A":
                            send_record.subject = subject
                            
                        if send_record.smtp_response == "N/A":
                            send_record.smtp_response = smtp_response
                            
                        if send_record.aws_process_time == -1:
                            send_record.aws_process_time = aws_process_time
                            
                        send_record.save()
                    except Exception as e:
                        logger.info("error well trying to get_or_create record: %s" % e)
                logger.info(
                    u'Received delivery notification: messageId: %s',
                    message_id,
                    extra={
                        'notification': notification,
                    },
                )

                signals.delivery_received.send(
                    sender=handle_bounce,
                    mail_obj=mail_obj,
                    delivery_obj=send_obj,
                    raw_message=raw_json,
                )
                
            else:
                # We received an unknown notification type. Just log and
                # ignore it.
                
                UnknownRecord.objects.create(
                        event_type = eventType,
                        aws_data = str(notification)
                    )
                
                logger.warning(u"Received unknown event", extra={
                    'notification': notification,
                })
    else:
        
        UnknownRecord.objects.create(
                eventType = notification.get('Type'),
                aws_data = str(notification)
            )
        
        logger.info(
            u'Received unknown notification type: %s',
            notification.get('Type'),
            extra={
                'notification': notification,
            },
        )

    # AWS will consider anything other than 200 to be an error response and
    # resend the SNS request. We don't need that so we return 200 here.
    return HttpResponse()

class HandleUnsubscribe(TemplateView): 
    
    http_method_names = ['get']
    
    template_name = settings.UNSUBSCRIBE_TEMPLET
    base_template_name =  settings.BASE_TEMPLET 
    unsubscribe_message = "We Have Unsubscribed the Following Email"   
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        logger.info("in get_context_data ----- self.base_template_name: %s" % self.base_template_name)
        context['base_template_name'] = self.base_template_name
        context['unsubscribe_message'] = self.unsubscribe_message
        return context  
    
    def get(self, request, *args, **kwargs):
        uuid = self.kwargs['uuid']
        hash = self.kwargs['hash']
        
        logger.info("in get ----- self.base_template_name: %s" % self.base_template_name)
        
        try:
            uuid = force_text(urlsafe_base64_decode(uuid).decode())
            logger.info('uuid: %s' % uuid)
            user = User.objects.get(pk=uuid)
            logger.info('user.pk: %s' % user.pk)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return redirect(settings.HOME_URL)
        try:
            ses = user.aws_ses
        except AwsSesUserAddon.DoesNotExist:
            ses = AwsSesUserAddon.objects.create(user=user)
            
        if user is not None and user.aws_ses.check_unsubscribe_hash(hash):
            logger.info('ses.pk: %s' % ses.pk)
            ses.unsubscribe = True
            ses.save()
        else:
            logger.warning("bad hash was provided!")
            return redirect(settings.HOME_URL)
        
        return super(HandleUnsubscribe, self).get(request, *args, **kwargs)