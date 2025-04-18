from django.test import TestCase, RequestFactory, override_settings
from django.core.mail import EmailMessage
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from unittest.mock import patch, Mock
import json

from .backends import SESBackend
from .views import handle_bounce, HandleUnsubscribe
from .utils import filter_recipients
from .models import BounceRecord, ComplaintRecord, AwsSesUserAddon, AwsSesSettings

User = get_user_model()

@override_settings(
    AWS_SES_ACCESS_KEY_ID='test-key',
    AWS_SES_SECRET_ACCESS_KEY='test-secret',
    AWS_SES_REGION_NAME='us-east-1',
    AWS_SES_REGION_ENDPOINT='email.us-east-1.amazonaws.com',
    EMAIL_BACKEND='django_aws_ses.backends.SESBackend',
    SES_BOUNCE_LIMIT=1,
    TESTING=True,
)
class DjangoAwsSesTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        # Use get_or_create to avoid duplicate Site creation
        self.site, _ = Site.objects.get_or_create(
            id=1, defaults={'domain': 'example.com', 'name': 'example.com'}
        )
        # Create AwsSesSettings for the Site
        AwsSesSettings.objects.get_or_create(
            site=self.site,
            defaults={
                'access_key': 'test-key',
                'secret_key': 'test-secret',
                'region_name': 'us-east-1',
                'region_endpoint': 'email.us-east-1.amazonaws.com'
            }
        )
        # Create test user
        self.user = User.objects.create_user(
            username='testuser', email='test@example.com', password='testpass'
        )
        self.ses_addon = AwsSesUserAddon.objects.create(user=self.user)

    @patch('boto3.client')
    def test_email_sending(self, mock_boto_client):
        """Test sending an email via SESBackend."""
        mock_ses = Mock()
        mock_ses.send_raw_email.return_value = {
            'MessageId': 'test-id',
            'ResponseMetadata': {'RequestId': 'test-request-id'}
        }
        mock_boto_client.return_value = mock_ses

        backend = SESBackend()
        message = EmailMessage(
            subject='Test',
            body='Hello',
            from_email='from@example.com',
            to=['to@example.com']
        )
        sent, _ = backend.send_messages([message])

        self.assertEqual(sent, 1)
        self.assertEqual(message.extra_headers['message_id'], 'test-id')

    def test_bounce_handling(self):
        """Test handling an SNS bounce notification."""
        notification = {
            'Type': 'Notification',
            'Message': json.dumps({
                'notificationType': 'Bounce',
                'mail': {'destination': ['test@example.com']},
                'bounce': {
                    'feedbackId': 'test-feedback',
                    'bounceType': 'Permanent',
                    'bounceSubType': 'General',
                    'bouncedRecipients': [{'emailAddress': 'test@example.com'}]
                }
            })
        }
        request = self.factory.post('/aws_ses/bounce/', data=notification, content_type='application/json')
        with patch('django_aws_ses.utils.verify_bounce_message', return_value=True):
            response = handle_bounce(request)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(BounceRecord.objects.filter(email='test@example.com').exists())

    def test_complaint_handling(self):
        """Test handling an SNS complaint notification."""
        notification = {
            'Type': 'Notification',
            'Message': json.dumps({
                'notificationType': 'Complaint',
                'mail': {'destination': ['test@example.com']},
                'complaint': {
                    'feedbackId': 'test-feedback',
                    'complaintFeedbackType': 'abuse',
                    'complainedRecipients': [{'emailAddress': 'test@example.com'}]
                }
            })
        }
        request = self.factory.post('/aws_ses/bounce/', data=notification, content_type='application/json')
        with patch('django_aws_ses.utils.verify_bounce_message', return_value=True):
            response = handle_bounce(request)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(ComplaintRecord.objects.filter(email='test@example.com').exists())

    def test_unsubscribe_confirmation(self):
        """Test unsubscribe confirmation page and action."""
        uuid = urlsafe_base64_encode(force_bytes(str(self.user.pk)))
        hash_value = self.ses_addon.unsubscribe_hash_generator()
        url = reverse('django_aws_ses:aws_ses_unsubscribe', kwargs={'uuid': uuid, 'hash': hash_value})

        # Test GET (confirmation page)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Please confirm your subscription preference')
        self.assertFalse(self.ses_addon.unsubscribe)

        # Test POST (unsubscribe)
        response = self.client.post(url, {'action': 'unsubscribe'})
        self.ses_addon.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'You have been unsubscribed')
        self.assertTrue(self.ses_addon.unsubscribe)

    def test_resubscribe_confirmation(self):
        """Test re-subscribe confirmation action."""
        self.ses_addon.unsubscribe = True
        self.ses_addon.save()
        uuid = urlsafe_base64_encode(force_bytes(str(self.user.pk)))
        hash_value = self.ses_addon.unsubscribe_hash_generator()
        url = reverse('django_aws_ses:aws_ses_unsubscribe', kwargs={'uuid': uuid, 'hash': hash_value})

        response = self.client.post(url, {'action': 'resubscribe'})
        self.ses_addon.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'You have been re-subscribed')
        self.assertFalse(self.ses_addon.unsubscribe)

    def test_recipient_filtering(self):
        """Test recipient filtering for blacklisted emails."""
        BounceRecord.objects.create(email='bounce@example.com')
        ComplaintRecord.objects.create(email='complaint@example.com')
        recipients = ['test@example.com', 'bounce@example.com', 'complaint@example.com']
        filtered = filter_recipients(recipients)
        self.assertEqual(filtered, ['test@example.com'])