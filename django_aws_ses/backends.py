import logging
from time import sleep
from datetime import datetime, timedelta

import boto3
from django.core.cache import cache
from django.core.mail.backends.base import BaseEmailBackend
from django.core.exceptions import ImproperlyConfigured
from requests.exceptions import RequestException as ResponseError

from . import settings
from . import signals
from . import utils

logger = settings.logger


def dkim_sign(message, dkim_domain=None, dkim_key=None, dkim_selector=None, dkim_headers=None):
    """Sign an email message with DKIM if the package and settings are available.

    Args:
        message (str): The email message as a string.
        dkim_domain (str): DKIM domain for signing.
        dkim_key (str): DKIM private key.
        dkim_selector (str): DKIM selector.
        dkim_headers (tuple): Headers to include in DKIM signing.

    Returns:
        str: The signed message or original message if signing fails.
    """
    try:
        import dkim
    except ImportError:
        logger.warning("DKIM package not installed, skipping signing")
        return message

    if not (dkim_domain and dkim_key):
        logger.debug("DKIM domain or key missing, skipping signing")
        return message

    try:
        sig = dkim.sign(
            message,
            dkim_selector,
            dkim_domain,
            dkim_key,
            include_headers=dkim_headers
        )
        return sig + message
    except Exception as e:
        logger.error(f"DKIM signing failed: {e}")
        return message


class SESBackend(BaseEmailBackend):
    """Django email backend for Amazon SES.

    Sends emails using AWS SES with support for DKIM signing and rate limiting.
    """

    def __init__(self, fail_silently=False, aws_access_key=None, aws_secret_key=None,
                 aws_region_name=None, aws_region_endpoint=None, aws_auto_throttle=None,
                 dkim_domain=None, dkim_key=None, dkim_selector=None, dkim_headers=None, **kwargs):
        """Initialize SES backend with AWS credentials and settings.

        Args:
            fail_silently (bool): If True, silently ignore errors.
            aws_access_key (str): AWS access key ID.
            aws_secret_key (str): AWS secret access key.
            aws_region_name (str): AWS region name.
            aws_region_endpoint (str): AWS SES endpoint URL.
            aws_auto_throttle (float): Throttling factor for SES rate limits.
            dkim_domain (str): DKIM domain for signing.
            dkim_key (str): DKIM private key.
            dkim_selector (str): DKIM selector.
            dkim_headers (tuple): Headers to include in DKIM signing.

        Raises:
            ImproperlyConfigured: If AWS credentials are missing.
        """
        super().__init__(fail_silently=fail_silently, **kwargs)
        self._access_key_id = aws_access_key or settings.ACCESS_KEY
        self._access_key = aws_secret_key or settings.SECRET_KEY
        self._region_name = aws_region_name or settings.AWS_SES_REGION_NAME
        self._endpoint_url = aws_region_endpoint or settings.AWS_SES_REGION_ENDPOINT
        self._throttle = aws_auto_throttle or settings.AWS_SES_AUTO_THROTTLE
        self.dkim_domain = dkim_domain or settings.DKIM_DOMAIN
        self.dkim_key = dkim_key or settings.DKIM_PRIVATE_KEY
        self.dkim_selector = dkim_selector or settings.DKIM_SELECTOR
        self.dkim_headers = dkim_headers or settings.DKIM_HEADERS

        if not (self._access_key_id and self._access_key):
            raise ImproperlyConfigured("AWS SES credentials are required.")

        self.connection = None

    def open(self):
        """Create a connection to the AWS SES API server.

        Returns:
            bool: True if a new connection was created, False otherwise.
        """
        if self.connection:
            return False

        try:
            self.connection = boto3.client(
                'ses',
                aws_access_key_id=self._access_key_id,
                aws_secret_access_key=self._access_key,
                region_name=self._region_name,
                endpoint_url=self._endpoint_url,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to SES: {e}")
            if not self.fail_silently:
                raise
            return False

    def close(self):
        """Close the SES API connection."""
        self.connection = None

    def get_rate_limit(self):
        """Retrieve and cache the SES maximum send rate.

        Returns:
            float: The maximum send rate per second.

        Raises:
            Exception: If no connection is available to fetch the rate limit.
        """
        cache_key = f"ses_rate_limit_{self._access_key_id}"
        rate_limit = cache.get(cache_key)
        if rate_limit is not None:
            logger.debug(f"Retrieved cached rate limit: {rate_limit}")
            return rate_limit

        logger.debug("Fetching new rate limit from AWS SES")
        new_conn_created = self.open()
        if not self.connection:
            raise Exception("No connection to check SES rate limit.")

        try:
            quota_dict = self.connection.get_send_quota()
            rate_limit = float(quota_dict['MaxSendRate'])
            cache.set(cache_key, rate_limit, timeout=3600)  # Cache for 1 hour
            return rate_limit
        finally:
            if new_conn_created:
                self.close()

    def send_messages(self, email_messages):
        """Send one or more EmailMessage objects.

        Args:
            email_messages (list): List of EmailMessage objects to send.

        Returns:
            tuple: (number of messages sent, dictionary with sent/not sent info)
        """
        if not email_messages:
            logger.debug("No email messages to send")
            return 0, {"Sent": ""}

        new_conn_created = self.open()
        if not self.connection:
            logger.error("Failed to establish SES connection")
            return 0, {"Sent": ""}

        num_sent, sent_message, list_of_response = 0, {"Sent": ""}, []
        source = settings.AWS_SES_RETURN_PATH or settings.DEFAULT_FROM_EMAIL
        not_sent_list = []

        for message in email_messages:
            message.aws_ses_response = {'error': 'not sent yet'}
            signals.email_pre_send.send_robust(self.__class__, message=message)

            pre_filter_recipients = message.recipients()
            message.to = utils.filter_recipients(message.to)
            message.cc = utils.filter_recipients(message.cc)
            message.bcc = utils.filter_recipients(message.bcc)

            if not message.recipients():
                logger.debug("No recipients after filtering")
                message.aws_ses_response = {'error': 'no recipients left after filtering'}
                list_of_response.append({'error': 'no recipients left after filtering'})
                continue

            not_sent_list.extend([email for email in pre_filter_recipients if email not in message.recipients()])

            if settings.AWS_SES_CONFIGURATION_SET and 'X-SES-CONFIGURATION-SET' not in message.extra_headers:
                if callable(settings.AWS_SES_CONFIGURATION_SET):
                    message.extra_headers['X-SES-CONFIGURATION-SET'] = settings.AWS_SES_CONFIGURATION_SET(
                        message, dkim_domain=self.dkim_domain, dkim_key=self.dkim_key,
                        dkim_selector=self.dkim_selector, dkim_headers=self.dkim_headers
                    )
                else:
                    message.extra_headers['X-SES-CONFIGURATION-SET'] = settings.AWS_SES_CONFIGURATION_SET

            if self._throttle:
                now = datetime.now()
                cache_key = "ses_recent_send_times"
                recent_send_times = cache.get(cache_key, [])
                window = 2.0
                window_start = now - timedelta(seconds=window)
                recent_send_times = [t for t in recent_send_times if t > window_start]

                rate_limit = self.get_rate_limit()
                if len(recent_send_times) > rate_limit * window * self._throttle:
                    delta = now - recent_send_times[0]
                    total_seconds = delta.total_seconds()
                    delay = window - total_seconds
                    if delay > 0:
                        sleep(delay)

                recent_send_times.append(now)
                cache.set(cache_key, recent_send_times, timeout=2)

            try:
                response = self.connection.send_raw_email(
                    Source=source or message.from_email,
                    Destinations=message.recipients(),
                    RawMessage={'Data': dkim_sign(
                        message.message().as_string(),
                        dkim_key=self.dkim_key,
                        dkim_domain=self.dkim_domain,
                        dkim_selector=self.dkim_selector,
                        dkim_headers=self.dkim_headers
                    )}
                )
                message.aws_ses_response = response
                message.extra_headers.update({
                    'status': 200,
                    'message_id': response['MessageId'],
                    'request_id': response['ResponseMetadata']['RequestId']
                })
                num_sent += 1
                logger.info(
                    f"Sent email from {message.from_email} to {', '.join(message.recipients())}, "
                    f"message_id={message.extra_headers['message_id']}, request_id={message.extra_headers['request_id']}"
                )
                list_of_response.append(response)
                signals.email_post_send.send_robust(self.__class__, message=message)
            except ResponseError as err:
                logger.error(f"Failed to send email: {err}")
                message.extra_headers.update({
                    key: getattr(err, key, None) for key in ['status', 'reason', 'body', 'request_id', 'error_code', 'error_message']
                })
                list_of_response.append({'error': str(err)})
                if not self.fail_silently:
                    raise

        if not_sent_list:
            sent_message["Sent"] = ", ".join(not_sent_list)

        if new_conn_created:
            self.close()

        logger.debug(f"Sent {num_sent} messages, response: {list_of_response}")
        return num_sent, sent_message