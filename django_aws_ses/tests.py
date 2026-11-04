from django.test import TestCase, RequestFactory, override_settings
from django.core.mail import EmailMessage
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from unittest.mock import patch, Mock
import datetime
import json

from .backends import SESBackend
from .views import handle_bounce, stats_to_list
from .utils import filter_recipients
from .models import BounceRecord, ComplaintRecord, AwsSesUserAddon

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

        # Create test user
        self.user = User.objects.create_user(
            username='testuser', email='test@example.com', password='testpass'
        )
        # Retrieve the AwsSesUserAddon created by the post_save signal
        self.ses_addon = AwsSesUserAddon.objects.get(user=self.user)
        # Reset client session to prevent state interference
        self.client = self.client_class()

    @patch('boto3.client')
    def test_email_sending(self, mock_boto_client):
        """Test sending an email via SESBackend."""
        mock_ses = Mock()
        mock_ses.send_raw_email.return_value = {
            'MessageId': 'test-id',
            'ResponseMetadata': {'RequestId': 'test-request-id'}
        }
        mock_ses.get_send_quota.return_value = {
            'MaxSendRate': 10.0,
            'Max24HourSend': 20000.0,
            'SentLast24Hours': 1000.0
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
        uuid_b64 = urlsafe_base64_encode(str(self.user.pk).encode())
        token = self.ses_addon.generate_unsubscribe_token()
        url = reverse('django_aws_ses:aws_ses_unsubscribe', kwargs={'uuid': uuid_b64, 'token': token})

        # Test GET (confirmation page)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Please confirm your email subscription preference', html=True)
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
        uuid_b64 = urlsafe_base64_encode(str(self.user.pk).encode())
        token = self.ses_addon.generate_unsubscribe_token()
        url = reverse('django_aws_ses:aws_ses_unsubscribe', kwargs={'uuid': uuid_b64, 'token': token})

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


# ---------------------------------------------------------------------------
# Unsubscribe hardening (0.1.7): tokens, one-click, headers, filters
# ---------------------------------------------------------------------------
from django.core import signing
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMultiAlternatives
from django.test import Client

from . import settings as aws_ses_settings
from . import unsubscribe
from .models import EmailUnsubscribe, SendRecord, BlackListedDomains

ONE_CLICK_BASE = 'https://api.example.com'


def _mock_ses():
    mock_ses = Mock()
    mock_ses.send_raw_email.return_value = {
        'MessageId': 'test-id',
        'ResponseMetadata': {'RequestId': 'test-request-id'},
    }
    mock_ses.get_send_quota.return_value = {
        'MaxSendRate': 10.0, 'Max24HourSend': 20000.0, 'SentLast24Hours': 0.0,
    }
    return mock_ses


def _send_raw(message, **backend_kwargs):
    """Send `message` through SESBackend with SES mocked; return (sent, raw bytes or None)."""
    mock_ses = _mock_ses()
    with patch('boto3.client', return_value=mock_ses), \
            patch('django_aws_ses.utils.validater_email_domain', return_value=True):
        sent, _ = SESBackend(**backend_kwargs).send_messages([message])
    raw = None
    if mock_ses.send_raw_email.called:
        raw = mock_ses.send_raw_email.call_args.kwargs['RawMessage']['Data']
    return sent, raw


def _header_block(raw, name):
    """Return the header line for `name` plus any folded continuation lines."""
    lines = raw.splitlines()
    for i, line in enumerate(lines):
        if line.lower().startswith(name.lower() + ':'):
            block = [line]
            for cont in lines[i + 1:]:
                if cont.startswith((' ', '\t')):
                    block.append(cont)
                else:
                    break
            return block
    return []


class _UnsubscribeFixturesMixin:
    """Creates one user (with AwsSesUserAddon via signal) and one EmailUnsubscribe."""

    def setUp(self):
        self.user = User.objects.create_user(username='alice', email='alice@example.com', password='pw')
        self.addon = AwsSesUserAddon.objects.get(user=self.user)
        self.email_record = EmailUnsubscribe.objects.create(email='list@example.com')

    def records(self):
        """(label, record, refresh-and-read-state) for both record kinds."""
        return [
            ('user', self.addon, lambda: AwsSesUserAddon.objects.get(pk=self.addon.pk).unsubscribe),
            ('email', self.email_record, lambda: EmailUnsubscribe.objects.get(pk=self.email_record.pk).unsubscribed),
        ]


class UnsubscribeTokenTests(_UnsubscribeFixturesMixin, TestCase):
    """Test signed unsubscribe tokens (new format and legacy <= 0.1.6 format)"""

    def test_token_round_trip(self):
        """Test new-format tokens resolve to their record and verify"""
        print("\n✓ Testing new-format token round trip")
        print("  → Generating user and email tokens")
        user_token = self.addon.generate_unsubscribe_token()
        email_token = self.email_record.generate_token()
        self.assertEqual(
            signing.loads(user_token, salt=unsubscribe.TOKEN_SALT), {'kind': 'user', 'id': str(self.user.pk)}
        )
        self.assertEqual(
            signing.loads(email_token, salt=unsubscribe.TOKEN_SALT), {'kind': 'email', 'id': str(self.email_record.pk)}
        )
        print("  → Verifying and resolving tokens")
        self.assertTrue(self.addon.verify_unsubscribe_token(user_token))
        self.assertTrue(self.email_record.verify_token(email_token))
        self.assertEqual(unsubscribe.resolve_token(user_token), self.addon)
        self.assertEqual(unsubscribe.resolve_token(email_token), self.email_record)
        print("  → Tokens round-trip correctly")

    def test_tokens_do_not_contain_email(self):
        """Test the address is not readable from new tokens or generated URLs"""
        print("\n✓ Testing tokens and URLs carry no email address")
        print("  → Checking tokens and URLs for the address (plain and base64)")
        for token, url, email in [
            (self.addon.generate_unsubscribe_token(), self.addon.unsubscribe_url_generator(), 'alice@example.com'),
            (self.email_record.generate_token(), self.email_record.unsubscribe_url_generator(), 'list@example.com'),
        ]:
            encoded = urlsafe_base64_encode(email.encode())
            for value in (token, url):
                self.assertNotIn(email, value)
                self.assertNotIn(encoded, value)
                self.assertNotIn('example', value)
        print("  → No address found in tokens or URLs")

    def test_tampered_tokens_rejected(self):
        """Test tampered/forged tokens - expects rejection"""
        print("\n⚠ Testing tampered tokens (expecting rejection)")
        user_token = self.addon.generate_unsubscribe_token()
        other = User.objects.create_user(username='bob', email='bob@example.com', password='pw')
        forged = [
            ('signature altered', user_token[:-1] + ('A' if user_token[-1] != 'A' else 'B')),
            ('payload swapped', signing.dumps({'kind': 'user', 'id': str(other.pk)}, salt='wrong-salt')),
            ('wrong kind', unsubscribe.make_token('email', self.user.pk)),
            ('garbage', 'not-a-token'),
            ('empty', ''),
        ]
        for label, token in forged:
            print(f"  → Testing {label} token (rejected expected)")
            self.assertFalse(self.addon.verify_unsubscribe_token(token))
            if label != 'wrong kind':
                self.assertIsNone(unsubscribe.resolve_token(token))
        print("  → Testing another user's valid token against this user (rejected expected)")
        self.assertFalse(self.addon.verify_unsubscribe_token(other.aws_ses.generate_unsubscribe_token()))
        print("  → Testing email token for another record (rejected expected)")
        other_record = EmailUnsubscribe.objects.create(email='other@example.com')
        self.assertFalse(self.email_record.verify_token(other_record.generate_token()))
        print("  ✓ Tampered tokens rejected")

    def test_legacy_tokens_still_verify(self):
        """Test tokens issued by <= 0.1.6 still verify and resolve"""
        print("\n✓ Testing legacy (<= 0.1.6) tokens still work")
        print("  → Building legacy tokens with Signer()")
        legacy_user = signing.Signer().sign(f"{self.user.pk}:alice@example.com")
        legacy_email = signing.Signer().sign('list@example.com')
        self.assertTrue(self.addon.verify_unsubscribe_token(legacy_user))
        self.assertTrue(self.email_record.verify_token(legacy_email))
        self.assertEqual(unsubscribe.resolve_token(legacy_user), self.addon)
        self.assertEqual(unsubscribe.resolve_token(legacy_email), self.email_record)
        print("  → Legacy tokens verified and resolved")

    def test_legacy_tokens_rejected_when_disabled_or_mismatched(self):
        """Test legacy token edge cases - expects rejection"""
        print("\n⚠ Testing legacy token rejection cases")
        legacy_user = signing.Signer().sign(f"{self.user.pk}:alice@example.com")
        legacy_email = signing.Signer().sign('list@example.com')
        print("  → Testing legacy tokens with AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS=False")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS', False):
            self.assertFalse(self.addon.verify_unsubscribe_token(legacy_user))
            self.assertFalse(self.email_record.verify_token(legacy_email))
            self.assertIsNone(unsubscribe.resolve_token(legacy_user))
        print("  → Testing legacy email token against a user record (no crash)")
        self.assertFalse(self.addon.verify_unsubscribe_token(legacy_email))
        print("  → Testing legacy user token after the user's email changed")
        self.user.email = 'changed@example.com'
        self.user.save()
        self.assertIsNone(unsubscribe.resolve_token(legacy_user))
        print("  ✓ Legacy edge cases rejected")


class UnsubscribeUrlTests(_UnsubscribeFixturesMixin, TestCase):
    """Test unsubscribe URL generation and AWS_SES_UNSUBSCRIBE_URL"""

    def test_default_urls_point_at_token_page(self):
        """Test generators default to the library's token confirmation page"""
        print("\n✓ Testing default unsubscribe URLs")
        for label, record, _ in self.records():
            print(f"  → Generating URL for {label} record")
            url = record.unsubscribe_url_generator()
            token = unsubscribe.token_for(record)
            self.assertEqual(
                url, reverse('django_aws_ses:aws_ses_unsubscribe_token', kwargs={'token': token})
            )
            self.assertTrue(url.startswith('/aws_ses/unsubscribe/token/'))
        print("  → Default URLs point at /unsubscribe/token/<token>/")

    def test_url_setting_format_string_and_callable(self):
        """Test AWS_SES_UNSUBSCRIBE_URL as a format string and a callable"""
        print("\n✓ Testing AWS_SES_UNSUBSCRIBE_URL")
        token = self.addon.generate_unsubscribe_token()
        print("  → Format string")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_URL', 'https://app.example.com/unsubscribe/{token}'):
            self.assertEqual(self.addon.unsubscribe_url_generator(), f'https://app.example.com/unsubscribe/{token}')
        print("  → Callable")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_URL', lambda t: f'https://app.example.com/u?t={t}'):
            self.assertEqual(self.addon.unsubscribe_url_generator(), f'https://app.example.com/u?t={token}')
        print("  → Frontend URLs generated")

    def test_url_setting_escapes_token(self):
        """Test AWS_SES_UNSUBSCRIBE_URL string form - expects token escaped, no injection or KeyError"""
        print("\n⚠ Testing AWS_SES_UNSUBSCRIBE_URL with hostile tokens (escaped, no error expected)")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_URL', 'https://app.example.com/unsub?token={token}'):
            print("  → Token containing & and = cannot add query parameters")
            self.assertEqual(unsubscribe.build_unsubscribe_url('x&admin=1'),
                             'https://app.example.com/unsub?token=x%26admin%3D1')
            print("  → Token containing / and # cannot add path segments or a fragment")
            self.assertEqual(unsubscribe.build_unsubscribe_url('a/b#c'),
                             'https://app.example.com/unsub?token=a%2Fb%23c')
        print("  → Other {...} in the URL are left alone (no KeyError)")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_URL', 'https://app.example.com/{lang}/u/{token}'):
            self.assertEqual(unsubscribe.build_unsubscribe_url('abc:def'), 'https://app.example.com/{lang}/u/abc:def')
        print("  ✓ Token escaped correctly")

    def test_old_routes_accept_new_tokens(self):
        """Test the existing uuid/encoded_email routes accept new-format tokens"""
        print("\n✓ Testing old routes with new tokens")
        print("  → GET old user route")
        url = reverse('django_aws_ses:aws_ses_unsubscribe', kwargs={
            'uuid': urlsafe_base64_encode(str(self.user.pk).encode()),
            'token': self.addon.generate_unsubscribe_token(),
        })
        self.assertEqual(self.client.get(url).status_code, 200)
        print("  → GET old email route")
        url = reverse('django_aws_ses:aws_ses_email_unsubscribe', kwargs={
            'encoded_email': urlsafe_base64_encode(b'list@example.com'),
            'token': self.email_record.generate_token(),
        })
        self.assertEqual(self.client.get(url).status_code, 200)
        print("  → Old routes render the confirmation page")


class ConfirmationPageTests(_UnsubscribeFixturesMixin, TestCase):
    """Test GET confirmation pages never change state; POST from the form does"""

    def _page_urls(self):
        return [
            ('old user route', reverse('django_aws_ses:aws_ses_unsubscribe', kwargs={
                'uuid': urlsafe_base64_encode(str(self.user.pk).encode()),
                'token': signing.Signer().sign(f"{self.user.pk}:alice@example.com"),
            }), lambda: AwsSesUserAddon.objects.get(pk=self.addon.pk).unsubscribe),
            ('old email route', reverse('django_aws_ses:aws_ses_email_unsubscribe', kwargs={
                'encoded_email': urlsafe_base64_encode(b'list@example.com'),
                'token': signing.Signer().sign('list@example.com'),
            }), lambda: EmailUnsubscribe.objects.get(pk=self.email_record.pk).unsubscribed),
            ('token route (user)', self.addon.unsubscribe_url_generator(),
             lambda: AwsSesUserAddon.objects.get(pk=self.addon.pk).unsubscribe),
            ('token route (email)', self.email_record.unsubscribe_url_generator(),
             lambda: EmailUnsubscribe.objects.get(pk=self.email_record.pk).unsubscribed),
        ]

    def test_get_does_not_change_state(self):
        """Test GET on every confirmation page leaves subscription state unchanged"""
        print("\n✓ Testing GET confirmation pages do not unsubscribe (link scanners)")
        for label, url, state in self._page_urls():
            print(f"  → GET {label}")
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, 'Please confirm your email subscription preference')
            self.assertFalse(state())
        print("  → No state changed by GET")

    def test_token_page_post_with_csrf_enforced(self):
        """Test the token page form works with CSRF enforced (template has csrf_token)"""
        print("\n✓ Testing token page POST with CSRF checks enforced")
        for label, record, state in self.records():
            client = Client(enforce_csrf_checks=True)
            url = record.unsubscribe_url_generator()
            print(f"  → GET form for {label} record and read CSRF token")
            response = client.get(url)
            self.assertContains(response, 'csrfmiddlewaretoken')
            csrf = client.cookies['csrftoken'].value
            print(f"  → POST unsubscribe for {label} record")
            response = client.post(url, {'action': 'unsubscribe', 'csrfmiddlewaretoken': csrf})
            self.assertContains(response, 'You have been unsubscribed')
            self.assertTrue(state())
            print(f"  → POST resubscribe for {label} record")
            response = client.post(url, {'action': 'resubscribe', 'csrfmiddlewaretoken': csrf})
            self.assertContains(response, 'You have been re-subscribed')
            self.assertFalse(state())
        print("  → Form POSTs work with CSRF enforced")

    def test_token_page_invalid_token(self):
        """Test token page with invalid token - expects redirect home"""
        print("\n⚠ Testing token page with an invalid token (302 to HOME_URL expected)")
        url = reverse('django_aws_ses:aws_ses_unsubscribe_token', kwargs={'token': 'bogus'})
        self.assertRedirects(self.client.get(url), '/', fetch_redirect_response=False)
        self.assertRedirects(self.client.post(url, {'action': 'unsubscribe'}), '/', fetch_redirect_response=False)
        print("  ✓ Invalid token redirected")

    def test_pages_mask_email(self):
        """Test every confirmation page shows the address masked, never in full"""
        print("\n✓ Testing confirmation pages mask the address")
        masked = {'alice@example.com': 'a***@example.com', 'list@example.com': 'l***@example.com'}
        for label, url, _ in self._page_urls():
            full = 'alice@example.com' if 'user' in label else 'list@example.com'
            print(f"  → GET and POST {label}")
            for response in (self.client.get(url), self.client.post(url, {'action': 'resubscribe'})):
                self.assertContains(response, masked[full])
                self.assertNotContains(response, full)
        print("  → Address masked on GET and POST")


class OneClickUnsubscribeTests(_UnsubscribeFixturesMixin, TestCase):
    """Test the RFC 8058 one-click endpoint"""

    def _url(self, record):
        return reverse('django_aws_ses:aws_ses_one_click_unsubscribe', kwargs={'token': unsubscribe.token_for(record)})

    def test_get_redirects_without_change(self):
        """Test GET/HEAD redirect to the confirmation page and never unsubscribe"""
        print("\n✓ Testing one-click GET/HEAD (302 to confirmation page, no change)")
        for label, record, state in self.records():
            print(f"  → GET and HEAD for {label} record")
            for response in (self.client.get(self._url(record)), self.client.head(self._url(record))):
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response['Location'], record.unsubscribe_url_generator())
            self.assertFalse(state())
        print("  → Testing GET redirect honours AWS_SES_UNSUBSCRIBE_URL")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_URL', 'https://app.example.com/u/{token}'):
            response = self.client.get(self._url(self.addon))
            self.assertTrue(response['Location'].startswith('https://app.example.com/u/'))
        print("  → GET never changes state")

    def test_get_invalid_token_redirects_home(self):
        """Test one-click GET with an unsigned token - expects redirect home, not to the frontend"""
        print("\n⚠ Testing one-click GET with an invalid token (302 to HOME_URL expected)")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_URL', 'https://app.example.com/unsub?token={token}'):
            for token in ('x&admin=1', 'bogus'):
                print(f"  → GET with token {token!r}")
                url = reverse('django_aws_ses:aws_ses_one_click_unsubscribe', kwargs={'token': token})
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response['Location'], '/')
        print("  ✓ Unsigned tokens never reach AWS_SES_UNSUBSCRIBE_URL")

    def test_other_methods_not_allowed(self):
        """Test non-GET/POST methods - expects Method Not Allowed"""
        print("\n⚠ Testing one-click PUT/DELETE (405 expected)")
        for label, record, state in self.records():
            print(f"  → PUT and DELETE for {label} record (405 expected)")
            self.assertEqual(self.client.put(self._url(record)).status_code, 405)
            self.assertEqual(self.client.delete(self._url(record)).status_code, 405)
            self.assertFalse(state())
        print("  ✓ Other methods rejected")

    def test_post_without_exact_body_rejected(self):
        """Test POST without List-Unsubscribe=One-Click - expects Bad Request"""
        print("\n⚠ Testing one-click POST without the exact body (400 expected)")
        bad_bodies = [
            ('empty body', '', 'application/x-www-form-urlencoded'),
            ('wrong value', 'List-Unsubscribe=Yes', 'application/x-www-form-urlencoded'),
            ('repeated key', 'List-Unsubscribe=One-Click&List-Unsubscribe=One-Click', 'application/x-www-form-urlencoded'),
            ('JSON body', '{"List-Unsubscribe": "One-Click"}', 'application/json'),
            ('action form', 'action=unsubscribe', 'application/x-www-form-urlencoded'),
        ]
        for label, record, state in self.records():
            for body_label, body, content_type in bad_bodies:
                print(f"  → {label} record, {body_label} (400 expected)")
                response = self.client.post(self._url(record), data=body, content_type=content_type)
                self.assertEqual(response.status_code, 400)
                self.assertFalse(state())
        print("  → Valid body with an invalid token (400 expected)")
        url = reverse('django_aws_ses:aws_ses_one_click_unsubscribe', kwargs={'token': 'bogus'})
        response = self.client.post(url, data='List-Unsubscribe=One-Click',
                                    content_type='application/x-www-form-urlencoded')
        self.assertEqual(response.status_code, 400)
        print("  ✓ Invalid one-click requests rejected without changes")

    def test_post_one_click_unsubscribes(self):
        """Test correct one-click POST unsubscribes (urlencoded and multipart)"""
        print("\n✓ Testing one-click POST unsubscribes")
        for label, record, state in self.records():
            print(f"  → urlencoded POST for {label} record, CSRF enforced")
            client = Client(enforce_csrf_checks=True)
            response = client.post(self._url(record), data='List-Unsubscribe=One-Click',
                                   content_type='application/x-www-form-urlencoded')
            self.assertEqual(response.status_code, 200)
            self.assertTrue(state())
            print(f"  → Repeat POST for {label} record is idempotent")
            response = client.post(self._url(record), data='List-Unsubscribe=One-Click',
                                   content_type='application/x-www-form-urlencoded')
            self.assertEqual(response.status_code, 200)
        print("  → multipart POST")
        unsubscribe.set_unsubscribed(self.addon, False)
        response = self.client.post(self._url(self.addon), {'List-Unsubscribe': 'One-Click'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AwsSesUserAddon.objects.get(pk=self.addon.pk).unsubscribe)
        print("  → Legacy token on one-click endpoint")
        unsubscribe.set_unsubscribed(self.email_record, False)
        url = reverse('django_aws_ses:aws_ses_one_click_unsubscribe',
                      kwargs={'token': signing.Signer().sign('list@example.com')})
        response = self.client.post(url, data='List-Unsubscribe=One-Click',
                                    content_type='application/x-www-form-urlencoded')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(EmailUnsubscribe.objects.get(pk=self.email_record.pk).unsubscribed)
        print("  → One-click unsubscribe completed")


class UnsubscribeApiTests(_UnsubscribeFixturesMixin, TestCase):
    """Test the JSON unsubscribe API"""

    def _url(self, record):
        return reverse('django_aws_ses:aws_ses_unsubscribe_api', kwargs={'token': unsubscribe.token_for(record)})

    def test_status_and_update(self):
        """Test GET status and POST true/false for both record kinds"""
        print("\n✓ Testing JSON unsubscribe API")
        expected_email = {'user': 'a***@example.com', 'email': 'l***@example.com'}
        for label, record, state in self.records():
            print(f"  → GET status for {label} record")
            response = self.client.get(self._url(record))
            self.assertEqual(response.json(), {'kind': label, 'unsubscribed': False, 'email': expected_email[label]})
            self.assertFalse(state())
            print(f"  → POST unsubscribed=true for {label} record")
            response = self.client.post(self._url(record), data='{"unsubscribed": true}',
                                        content_type='application/json')
            self.assertTrue(response.json()['unsubscribed'])
            self.assertTrue(state())
            print(f"  → POST unsubscribed=false for {label} record")
            response = self.client.post(self._url(record), data='{"unsubscribed": false}',
                                        content_type='application/json')
            self.assertFalse(response.json()['unsubscribed'])
            self.assertFalse(state())
        print("  → API status and updates work")

    def test_api_validation_errors(self):
        """Test API validation - expects Bad Request / Not Found / Method Not Allowed"""
        print("\n⚠ Testing JSON API validation (expecting errors)")
        url = self._url(self.addon)
        print("  → Invalid JSON (400 expected)")
        self.assertEqual(self.client.post(url, data='{nope', content_type='application/json').status_code, 400)
        print("  → Non-boolean value (400 expected)")
        self.assertEqual(self.client.post(url, data='{"unsubscribed": "yes"}',
                                          content_type='application/json').status_code, 400)
        print("  → Missing value (400 expected)")
        self.assertEqual(self.client.post(url, data='{}', content_type='application/json').status_code, 400)
        print("  → Invalid token (404 expected)")
        bad = reverse('django_aws_ses:aws_ses_unsubscribe_api', kwargs={'token': 'bogus'})
        self.assertEqual(self.client.get(bad).status_code, 404)
        print("  → PUT (405 expected)")
        self.assertEqual(self.client.put(url).status_code, 405)
        self.assertFalse(AwsSesUserAddon.objects.get(pk=self.addon.pk).unsubscribe)
        print("  ✓ API validation errors handled correctly")


class ListUnsubscribeHeaderTests(_UnsubscribeFixturesMixin, TestCase):
    """Test the List-Unsubscribe headers helper"""

    @patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_BASE_URL', ONE_CLICK_BASE + '/')
    def test_headers_helper(self):
        """Test headers for User, AwsSesUserAddon and EmailUnsubscribe"""
        print("\n✓ Testing list_unsubscribe_headers()")
        for label, obj, token in [
            ('User', self.user, self.addon.generate_unsubscribe_token()),
            ('AwsSesUserAddon', self.addon, self.addon.generate_unsubscribe_token()),
            ('EmailUnsubscribe', self.email_record, self.email_record.generate_token()),
        ]:
            print(f"  → Headers for {label}")
            expected_url = ONE_CLICK_BASE + reverse(
                'django_aws_ses:aws_ses_one_click_unsubscribe', kwargs={'token': token}
            )
            self.assertEqual(unsubscribe.list_unsubscribe_headers(obj), {
                'List-Unsubscribe': f'<{expected_url}>',
                'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
            })
        self.assertEqual(self.addon.list_unsubscribe_headers(), unsubscribe.list_unsubscribe_headers(self.addon))
        self.assertEqual(self.email_record.list_unsubscribe_headers(),
                         unsubscribe.list_unsubscribe_headers(self.email_record))
        print("  → Headers built with absolute one-click URL")

    def test_headers_require_base_url(self):
        """Test headers without AWS_SES_UNSUBSCRIBE_BASE_URL - expects ImproperlyConfigured"""
        print("\n⚠ Testing headers without AWS_SES_UNSUBSCRIBE_BASE_URL (ImproperlyConfigured expected)")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_BASE_URL', None):
            with self.assertRaises(ImproperlyConfigured):
                unsubscribe.list_unsubscribe_headers(self.addon)
        print("  ✓ Missing base URL reported, not guessed")


@patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_BASE_URL', ONE_CLICK_BASE)
class BackendUnsubscribeHeaderTests(_UnsubscribeFixturesMixin, TestCase):
    """Test List-Unsubscribe rendering and automatic headers in SESBackend"""

    def send(self, message):
        sent, raw = _send_raw(message)
        return sent, None if raw is None else raw.decode()

    def test_long_header_is_one_plain_line(self):
        """Test a long List-Unsubscribe header is not RFC 2047 encoded or folded"""
        print("\n✓ Testing List-Unsubscribe renders as one plain line")
        headers = unsubscribe.list_unsubscribe_headers(self.addon)
        long_url = f"{ONE_CLICK_BASE}/aws_ses/unsubscribe/one-click/{'A' * 180}/"
        for label, value in [('helper URL', headers['List-Unsubscribe']), ('200+ char URL', f'<{long_url}>')]:
            print(f"  → Sending message with {label}")
            message = EmailMultiAlternatives('Hi', 'Hello', 'from@example.com', ['alice@example.com'], headers={
                'List-Unsubscribe': value, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
            })
            message.attach_alternative('<p>Hello</p>', 'text/html')
            sent, raw = self.send(message)
            self.assertEqual(sent, 1)
            self.assertNotIn('=?utf-8?', raw)
            self.assertEqual(_header_block(raw, 'List-Unsubscribe'), [f'List-Unsubscribe: {value}'])
            self.assertEqual(_header_block(raw, 'List-Unsubscribe-Post'),
                             ['List-Unsubscribe-Post: List-Unsubscribe=One-Click'])
        print("  → Checking build_mime_message() directly")
        from .backends import build_mime_message
        message = EmailMessage('Hi', 'Hello', 'from@example.com', ['x@example.com'],
                               headers={'List-Unsubscribe': f'<{long_url}>'})
        as_string = build_mime_message(message).as_string()
        self.assertNotIn('=?utf-8?', as_string)
        self.assertIn(f'List-Unsubscribe: <{long_url}>\n', as_string)
        print("  → Header is a single unencoded line")

    def test_message_subclass_forwarding_kwargs(self):
        """Test a message subclass whose message() forwards **kwargs builds on every Django version"""
        print("\n✓ Testing message() subclass that forwards **kwargs")
        from .backends import build_mime_message

        class ForwardingMessage(EmailMultiAlternatives):
            def message(self, **kwargs):
                return super().message(**kwargs)

        long_url = f"{ONE_CLICK_BASE}/aws_ses/unsubscribe/one-click/{'A' * 180}/"
        message = ForwardingMessage('Hi', 'Hello', 'from@example.com', ['x@example.com'],
                                    headers={'List-Unsubscribe': f'<{long_url}>'})
        print("  → Building MIME message")
        as_string = build_mime_message(message).as_string()
        self.assertIn(f'List-Unsubscribe: <{long_url}>\n', as_string)
        print("  → Built without TypeError, header on one line")

    def test_auto_headers_require_base_url_at_init(self):
        """Test auto headers without AWS_SES_UNSUBSCRIBE_BASE_URL - expects ImproperlyConfigured at backend init"""
        print("\n⚠ Testing backend init with auto headers and no base URL (ImproperlyConfigured expected)")
        with patch.object(aws_ses_settings, 'AWS_SES_AUTO_LIST_UNSUBSCRIBE', True):
            print("  → Base URL missing: raises before any message is sent")
            with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_BASE_URL', None):
                with self.assertRaises(ImproperlyConfigured):
                    SESBackend(fail_silently=True)
            print("  → Base URL set: backend created")
            SESBackend()
        print("  → Auto headers off: base URL not required")
        with patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_BASE_URL', None):
            SESBackend()
        print("  ✓ Misconfiguration reported at init")

    @patch.object(aws_ses_settings, 'AWS_SES_AUTO_LIST_UNSUBSCRIBE', True)
    def test_auto_headers_added_for_single_mapped_recipient(self):
        """Test automatic headers for one recipient mapped to a user or EmailUnsubscribe"""
        print("\n✓ Testing automatic List-Unsubscribe headers")
        for label, recipient, record in [
            ('user (case/display name differ)', 'Alice <ALICE@example.com>', self.addon),
            ('email record', 'list@example.com', self.email_record),
        ]:
            print(f"  → Sending to {label}")
            sent, raw = self.send(EmailMessage('Hi', 'Hello', 'from@example.com', [recipient]))
            self.assertEqual(sent, 1)
            expected = unsubscribe.list_unsubscribe_headers(record)['List-Unsubscribe']
            self.assertEqual(_header_block(raw, 'List-Unsubscribe'), [f'List-Unsubscribe: {expected}'])
            self.assertIn('List-Unsubscribe-Post: List-Unsubscribe=One-Click', raw)
        print("  → Headers added for mapped single recipients")

    @patch.object(aws_ses_settings, 'AWS_SES_AUTO_LIST_UNSUBSCRIBE', True)
    def test_auto_headers_skipped(self):
        """Test automatic headers are skipped where they would be wrong"""
        print("\n✓ Testing automatic headers are skipped when not applicable")
        cases = [
            ('two recipients', EmailMessage('Hi', 'Hello', 'from@example.com',
                                            ['alice@example.com', 'list@example.com'])),
            ('to + cc recipients', EmailMessage('Hi', 'Hello', 'from@example.com',
                                                ['alice@example.com'], cc=['list@example.com'])),
            ('unmapped recipient', EmailMessage('Hi', 'Hello', 'from@example.com', ['nobody@example.com'])),
        ]
        transactional = EmailMessage('Hi', 'Hello', 'from@example.com', ['alice@example.com'])
        transactional.aws_ses_transactional = True
        cases.append(('transactional message', transactional))
        for label, message in cases:
            print(f"  → {label}")
            sent, raw = self.send(message)
            self.assertEqual(sent, 1)
            self.assertNotIn('List-Unsubscribe', raw)
        print("  → App-set header is kept, not replaced")
        sent, raw = self.send(EmailMessage('Hi', 'Hello', 'from@example.com', ['alice@example.com'],
                                           headers={'List-Unsubscribe': '<mailto:unsub@example.com>'}))
        self.assertEqual(_header_block(raw, 'List-Unsubscribe'), ['List-Unsubscribe: <mailto:unsub@example.com>'])
        self.assertNotIn('List-Unsubscribe-Post', raw)
        print("  → Automatic headers skipped correctly")

    def test_auto_headers_off_by_default(self):
        """Test no headers are added when AWS_SES_AUTO_LIST_UNSUBSCRIBE is off"""
        print("\n✓ Testing automatic headers are opt-in")
        sent, raw = self.send(EmailMessage('Hi', 'Hello', 'from@example.com', ['alice@example.com']))
        self.assertEqual(sent, 1)
        self.assertNotIn('List-Unsubscribe', raw)
        print("  → No headers added by default")

    def test_dkim_signs_list_unsubscribe_headers(self):
        """Test List-Unsubscribe headers are added to the DKIM header list when present"""
        print("\n✓ Testing DKIM header list includes List-Unsubscribe headers")
        message = EmailMessage('Hi', 'Hello', 'from@example.com', ['alice@example.com'],
                               headers=unsubscribe.list_unsubscribe_headers(self.addon))
        with patch('django_aws_ses.backends.dkim_sign', side_effect=lambda m, **kw: m) as mock_sign:
            self.send(message)
        dkim_headers = mock_sign.call_args.kwargs['dkim_headers']
        self.assertEqual(tuple(dkim_headers),
                         ('From', 'To', 'Cc', 'Subject', 'List-Unsubscribe', 'List-Unsubscribe-Post'))
        print("  → Without the headers the default list is unchanged")
        with patch('django_aws_ses.backends.dkim_sign', side_effect=lambda m, **kw: m) as mock_sign:
            self.send(EmailMessage('Hi', 'Hello', 'from@example.com', ['alice@example.com']))
        self.assertEqual(tuple(mock_sign.call_args.kwargs['dkim_headers']), ('From', 'To', 'Cc', 'Subject'))
        print("  → DKIM header list correct")


import base64
from unittest import skipUnless

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

try:
    import dkim
except ImportError:
    dkim = None

DKIM_DOMAIN = 'example.com'
DKIM_SELECTOR = 'ses'


def _signed_headers(raw):
    """Return the lower-cased header names in the DKIM-Signature h= tag."""
    signature = ''.join(_header_block(raw.decode(), 'DKIM-Signature'))
    tags = dict(
        tag.strip().split('=', 1) for tag in signature.split(':', 1)[1].split(';') if '=' in tag
    )
    return [h.strip().lower() for h in ''.join(tags['h'].split()).split(':')]


@skipUnless(dkim, 'dkimpy not installed')
@patch.object(aws_ses_settings, 'AWS_SES_UNSUBSCRIBE_BASE_URL', ONE_CLICK_BASE)
class DkimSigningTests(_UnsubscribeFixturesMixin, TestCase):
    """Test library-side DKIM signing with dkimpy, verified against the matching public key"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_key = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
        public_key = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )).decode()
        cls.dns_record = f'v=DKIM1; k=rsa; p={public_key}'.encode()

    def dnsfunc(self, name, timeout=5):
        """Stand-in DNS lookup serving the test public key for ses._domainkey.example.com."""
        if name == f'{DKIM_SELECTOR}._domainkey.{DKIM_DOMAIN}.'.encode():
            return self.dns_record
        return None

    def send(self, message, **backend_kwargs):
        kwargs = {'dkim_domain': DKIM_DOMAIN, 'dkim_key': self.private_key, 'dkim_selector': DKIM_SELECTOR}
        kwargs.update(backend_kwargs)
        return _send_raw(message, **kwargs)

    def test_message_is_signed_and_verifies(self):
        """Test the sent message carries a DKIM signature that verifies"""
        print("\n✓ Testing library-side DKIM signing")
        print("  → Sending message with DKIM domain, key and selector set")
        sent, raw = self.send(EmailMessage('Hi', 'Hello', 'from@example.com', ['alice@example.com']))
        self.assertEqual(sent, 1)
        self.assertIsInstance(raw, bytes)
        self.assertTrue(raw.startswith(b'DKIM-Signature:'))
        print("  → Verifying signature against the public key")
        self.assertTrue(dkim.verify(raw, dnsfunc=self.dnsfunc))
        self.assertEqual(_signed_headers(raw), ['from', 'to', 'cc', 'subject'])
        print("  → Signature verified, default headers signed")

    def test_list_unsubscribe_headers_are_signed(self):
        """Test List-Unsubscribe headers are covered by the DKIM signature when present"""
        print("\n✓ Testing DKIM signature covers List-Unsubscribe headers")
        message = EmailMessage('Hi', 'Hello', 'from@example.com', ['alice@example.com'],
                               headers=unsubscribe.list_unsubscribe_headers(self.addon))
        sent, raw = self.send(message)
        self.assertEqual(sent, 1)
        self.assertTrue(dkim.verify(raw, dnsfunc=self.dnsfunc))
        self.assertEqual(_signed_headers(raw),
                         ['from', 'to', 'cc', 'subject', 'list-unsubscribe', 'list-unsubscribe-post'])
        print("  → Changing List-Unsubscribe after signing breaks verification")
        tampered = raw.replace(b'List-Unsubscribe: <', b'List-Unsubscribe: <https://evil.example.com/>, <', 1)
        self.assertNotEqual(tampered, raw)
        self.assertFalse(dkim.verify(tampered, dnsfunc=self.dnsfunc))
        print("  → List-Unsubscribe headers signed")

    def test_without_key_sends_unsigned(self):
        """Test a message is sent unsigned when no DKIM key is configured"""
        print("\n⚠ Testing send without a DKIM key (unsigned message expected)")
        with patch.object(aws_ses_settings, 'DKIM_PRIVATE_KEY', None):
            sent, raw = self.send(EmailMessage('Hi', 'Hello', 'from@example.com', ['alice@example.com']),
                                  dkim_key=None)
        self.assertEqual(sent, 1)
        self.assertIsInstance(raw, bytes)
        self.assertNotIn(b'DKIM-Signature', raw)
        print("  ✓ Message sent unsigned")


class TransactionalMessageTests(_UnsubscribeFixturesMixin, TestCase):
    """Test the per-message transactional opt-out of the unsubscribe filter"""

    def send(self, message):
        sent, raw = _send_raw(message)
        return sent, None if raw is None else raw.decode()

    def setUp(self):
        super().setUp()
        unsubscribe.set_unsubscribed(self.addon, True)

    def test_default_filters_unsubscribed_user(self):
        """Test a normal message to an unsubscribed user is still dropped (default unchanged)"""
        print("\n⚠ Testing normal message to unsubscribed user (dropped expected)")
        sent, raw = self.send(EmailMessage('News', 'Hello', 'from@example.com', ['alice@example.com']))
        self.assertEqual(sent, 0)
        self.assertIsNone(raw)
        print("  ✓ Unsubscribed user filtered")

    def test_transactional_attribute_and_header(self):
        """Test transactional messages reach an unsubscribed user; marker header is stripped"""
        print("\n✓ Testing transactional messages bypass only the unsubscribe filter")
        print("  → Attribute aws_ses_transactional=True")
        message = EmailMessage('Reset', 'Code 123', 'from@example.com', ['alice@example.com'])
        message.aws_ses_transactional = True
        sent, raw = self.send(message)
        self.assertEqual(sent, 1)
        print("  → Header X-Django-AWS-SES-Transactional: 1")
        message = EmailMessage('Reset', 'Code 123', 'from@example.com', ['alice@example.com'],
                               headers={'X-Django-AWS-SES-Transactional': '1'})
        sent, raw = self.send(message)
        self.assertEqual(sent, 1)
        self.assertNotIn('transactional', raw.lower())
        self.assertIn('X-Django-AWS-SES-Transactional', message.extra_headers)
        print("  → Marker stripped from sent message, message object untouched")

    def test_transactional_still_blocked_by_complaint_and_bounce(self):
        """Test transactional messages still respect complaint and bounce filters"""
        print("\n⚠ Testing transactional message to complained/bounced address (dropped expected)")
        for label, create in [
            ('complaint', lambda: ComplaintRecord.objects.create(email='alice@example.com')),
            ('bounce', lambda: BounceRecord.objects.create(email='alice@example.com')),
        ]:
            ComplaintRecord.objects.all().delete()
            BounceRecord.objects.all().delete()
            create()
            print(f"  → {label} record present")
            message = EmailMessage('Reset', 'Code 123', 'from@example.com', ['alice@example.com'])
            message.aws_ses_transactional = True
            sent, raw = self.send(message)
            self.assertEqual(sent, 0)
        print("  ✓ Complaint and bounce filters still applied")


class RecipientFilterTests(TestCase):
    """Test case-insensitive, display-name-aware recipient filtering and bounce counting"""

    def setUp(self):
        self.user = User.objects.create_user(username='carol', email='Carol@Example.com', password='pw')

    @patch('django_aws_ses.utils.validater_email_domain', return_value=True)
    def test_case_insensitive_filters(self, _mock_domain):
        """Test complaint/bounce/unsubscribe match regardless of case"""
        print("\n✓ Testing case-insensitive filtering")
        print("  → Records stored lower-case, recipients mixed-case")
        ComplaintRecord.objects.create(email='complaint@example.com')
        BounceRecord.objects.create(email='bounce@example.com')
        self.assertEqual(
            filter_recipients(['Complaint@Example.COM', 'BOUNCE@example.com', 'ok@example.com']),
            ['ok@example.com'],
        )
        print("  → Records stored mixed-case, recipients lower-case")
        ComplaintRecord.objects.create(email='Upper@Example.com')
        self.assertEqual(filter_recipients(['upper@example.com', 'ok@example.com']), ['ok@example.com'])
        print("  → Unsubscribed user with mixed-case email")
        unsubscribe.set_unsubscribed(self.user, True)
        self.assertEqual(filter_recipients(['carol@example.com', 'ok@example.com']), ['ok@example.com'])
        print("  → Case-insensitive filtering works")

    @patch('django_aws_ses.utils.validater_email_domain', return_value=True)
    def test_bounce_limit_counts_per_address(self, _mock_domain):
        """Test SES_BOUNCE_LIMIT counts bounces per address"""
        print("\n✓ Testing bounce limit counting")
        BounceRecord.objects.create(email='once@example.com')
        BounceRecord.objects.create(email='twice@example.com')
        BounceRecord.objects.create(email='TWICE@example.com')
        recipients = ['once@example.com', 'twice@example.com', 'ok@example.com']
        print("  → Limit 2: one bounce kept, two bounces dropped")
        with patch.object(aws_ses_settings, 'SES_BOUNCE_LIMIT', 2):
            self.assertEqual(filter_recipients(list(recipients)), ['once@example.com', 'ok@example.com'])
        print("  → Limit 1: any bounce dropped")
        with patch.object(aws_ses_settings, 'SES_BOUNCE_LIMIT', 1):
            self.assertEqual(filter_recipients(list(recipients)), ['ok@example.com'])
        print("  → Limit 3: nothing dropped")
        with patch.object(aws_ses_settings, 'SES_BOUNCE_LIMIT', 3):
            self.assertEqual(filter_recipients(list(recipients)), recipients)
        print("  → Bounce limit applied per address")

    def test_display_name_recipients(self):
        """Test "Name <addr>" recipients are filtered and validated by their address"""
        print("\n✓ Testing display-name recipients")
        ComplaintRecord.objects.create(email='complaint@example.com')
        print("  → Complaint matched through a display name")
        with patch('django_aws_ses.utils.validater_email_domain', return_value=True):
            self.assertEqual(
                filter_recipients(['Bad <complaint@example.com>', 'Good Person <good@example.com>']),
                ['Good Person <good@example.com>'],
            )
        print("  → Domain check uses the bare domain")
        with patch('dns.resolver.query', return_value=['mx']) as mock_query:
            self.assertEqual(filter_recipients(['Good Person <good@Example.org>']), ['Good Person <good@Example.org>'])
            mock_query.assert_called_once_with('example.org', 'MX')
        print("  → Previously-sent address (different case) skips DNS")
        SendRecord.objects.create(source='from@example.com', destination='Sent@Example.com')
        with patch('dns.resolver.query') as mock_query:
            self.assertEqual(filter_recipients(['Someone <sent@example.com>']), ['Someone <sent@example.com>'])
            mock_query.assert_not_called()
        print("  → Blacklisted domain matched case-insensitively")
        BlackListedDomains.objects.create(domain='Blocked.example')
        with patch('dns.resolver.query', return_value=['mx']):
            self.assertEqual(filter_recipients(['X <x@blocked.EXAMPLE>']), [])
        print("  → Display-name recipients handled")

    @patch('django_aws_ses.utils.validater_email_domain', return_value=True)
    def test_email_unsubscribe_filter_opt_in(self, _mock_domain):
        """Test EmailUnsubscribe records are filtered only with AWS_SES_FILTER_EMAIL_UNSUBSCRIBES"""
        print("\n✓ Testing AWS_SES_FILTER_EMAIL_UNSUBSCRIBES")
        EmailUnsubscribe.objects.create(email='List@Example.com', unsubscribed=True)
        EmailUnsubscribe.objects.create(email='still@example.com', unsubscribed=False)
        recipients = ['list@example.com', 'still@example.com']
        print("  → Off (default): not filtered")
        self.assertEqual(filter_recipients(list(recipients)), recipients)
        print("  → On: unsubscribed address filtered")
        with patch.object(aws_ses_settings, 'AWS_SES_FILTER_EMAIL_UNSUBSCRIBES', True):
            self.assertEqual(filter_recipients(list(recipients)), ['still@example.com'])
        print("  → Opt-in filter works")

    @patch('django_aws_ses.utils.validater_email_domain', return_value=True)
    def test_email_unsubscribe_filtered_when_auto_headers_on(self, _mock_domain):
        """Test one-click unsubscribes of EmailUnsubscribe records are honoured when auto headers are on"""
        print("\n✓ Testing EmailUnsubscribe filtered whenever AWS_SES_AUTO_LIST_UNSUBSCRIBE is on")
        EmailUnsubscribe.objects.create(email='list@example.com', unsubscribed=True)
        recipients = ['list@example.com', 'other@example.com']
        print("  → Auto headers on, AWS_SES_FILTER_EMAIL_UNSUBSCRIBES off")
        with patch.object(aws_ses_settings, 'AWS_SES_AUTO_LIST_UNSUBSCRIBE', True):
            self.assertEqual(filter_recipients(list(recipients)), ['other@example.com'])
        print("  → Unsubscribed address dropped")


class StatsToListTests(TestCase):
    """Test SES send statistics parsing for the dashboard"""

    @override_settings(TIME_ZONE='America/New_York')
    def test_timestamps_localized_and_sorted(self):
        """Test UTC SES timestamps are converted to TIME_ZONE and sorted"""
        print("\n✓ Testing stats_to_list localizes and sorts datapoints")
        print("  → Setting up out-of-order UTC datapoints")
        later = datetime.datetime(2026, 1, 15, 18, 30, tzinfo=datetime.timezone.utc)
        earlier = datetime.datetime(2026, 1, 15, 12, 0, tzinfo=datetime.timezone.utc)
        stats = {'SendDataPoints': [{'Timestamp': later}, {'Timestamp': earlier}]}

        result = stats_to_list(stats)

        print("  → Datapoints sorted oldest first")
        self.assertEqual([dp['Timestamp'] for dp in result], [earlier, later])
        print("  → Timestamps converted to America/New_York (UTC-5 in January)")
        self.assertEqual(result[0]['Timestamp'].hour, 7)
        self.assertEqual(result[1]['Timestamp'].hour, 13)
        self.assertEqual(result[0]['Timestamp'].utcoffset(), datetime.timedelta(hours=-5))
        print("  → Datapoints localized correctly")


# ---------------------------------------------------------------------------
# SNS signature verification on the bounce endpoint
# ---------------------------------------------------------------------------
import base64

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from django.core.cache import cache

from . import utils as aws_ses_utils
from .utils import verify_bounce_message

SNS_CERT_URL = 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem'
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:ses-notifications'
OTHER_TOPIC_ARN = 'arn:aws:sns:us-east-1:999999999999:attacker-topic'
SNS_SUBSCRIBE_URL = (
    'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription'
    '&TopicArn=arn:aws:sns:us-east-1:123456789012:ses-notifications&Token=abc'
)

# Fields SNS signs for each message type, in signing order (AWS SNS docs).
_SNS_SIGNED_FIELDS = {
    'Notification': ('Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type'),
    'SubscriptionConfirmation': (
        'Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type',
    ),
    'UnsubscribeConfirmation': (
        'Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type',
    ),
}


def _make_signing_cert():
    """Return (private key, PEM bytes) for a throwaway self-signed certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'sns.amazonaws.com')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM)


def _cert_response(pem):
    response = Mock()
    response.status_code = 200
    response.content = pem
    response.raise_for_status.return_value = None
    return response


class SnsSignatureVerificationTests(TestCase):
    """Test SNS signature verification on bounce/complaint notifications"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key, cls.pem = _make_signing_cert()

    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()

    def _sign(self, payload, version='1'):
        """Sign `payload` in place the way SNS does, building the string-to-sign independently."""
        lines = []
        for field in _SNS_SIGNED_FIELDS[payload['Type']]:
            if field in payload:
                lines.append(f"{field}\n{payload[field]}\n")
        hash_class = hashes.SHA256 if version == '2' else hashes.SHA1
        signature = self.key.sign(''.join(lines).encode('utf-8'), padding.PKCS1v15(), hash_class())
        payload['SignatureVersion'] = version
        payload['Signature'] = base64.b64encode(signature).decode('ascii')
        return payload

    def _notification(self, event='Bounce', topic_arn=SNS_TOPIC_ARN, version='1', **overrides):
        if event == 'Bounce':
            message = {
                'notificationType': 'Bounce',
                'mail': {'destination': ['bounced@example.com']},
                'bounce': {
                    'feedbackId': 'feedback-1',
                    'bounceType': 'Permanent',
                    'bounceSubType': 'General',
                    'bouncedRecipients': [{'emailAddress': 'bounced@example.com'}],
                },
            }
        else:
            message = {
                'notificationType': 'Complaint',
                'mail': {'destination': ['complained@example.com']},
                'complaint': {
                    'feedbackId': 'feedback-2',
                    'complaintFeedbackType': 'abuse',
                    'complainedRecipients': [{'emailAddress': 'complained@example.com'}],
                },
            }
        payload = {
            'Type': 'Notification',
            'MessageId': 'message-1',
            'TopicArn': topic_arn,
            'Message': json.dumps(message),
            'Timestamp': '2026-11-03T12:00:00.000Z',
            'SigningCertURL': SNS_CERT_URL,
        }
        payload.update(overrides)
        return self._sign(payload, version)

    def _subscription(self, topic_arn=SNS_TOPIC_ARN, subscribe_url=SNS_SUBSCRIBE_URL,
                      message_type='SubscriptionConfirmation'):
        return self._sign({
            'Type': message_type,
            'MessageId': 'message-2',
            'Token': 'abc',
            'TopicArn': topic_arn,
            'Message': 'You have chosen to subscribe to the topic.',
            'SubscribeURL': subscribe_url,
            'Timestamp': '2026-11-03T12:00:00.000Z',
            'SigningCertURL': SNS_CERT_URL,
        })

    def _post(self, payload):
        request = self.factory.post('/aws_ses/bounce/', data=payload, content_type='application/json')
        return handle_bounce(request)

    def test_valid_signatures_verify(self):
        """Test SignatureVersion 1 (SHA1) and 2 (SHA256) messages verify"""
        print("\n✓ Testing valid SNS signatures verify")
        with patch('requests.get', return_value=_cert_response(self.pem)):
            print("  → SignatureVersion 1 (SHA1)")
            self.assertTrue(verify_bounce_message(self._notification(version='1')))
            print("  → SignatureVersion 2 (SHA256)")
            self.assertTrue(verify_bounce_message(self._notification(version='2')))
            print("  → SubscriptionConfirmation")
            self.assertTrue(verify_bounce_message(self._subscription()))
        print("  → All signatures verified")

    def test_invalid_signatures_rejected(self):
        """Test tampered, missing and unsupported signatures - expects rejection"""
        print("\n⚠ Testing invalid signatures (expecting rejection)")
        with patch('requests.get', return_value=_cert_response(self.pem)):
            print("  → Message changed after signing")
            payload = self._notification()
            payload['Message'] = payload['Message'].replace('bounced@', 'victim@')
            self.assertFalse(verify_bounce_message(payload))

            print("  → Signature missing")
            payload = self._notification()
            del payload['Signature']
            self.assertFalse(verify_bounce_message(payload))

            print("  → Unsupported SignatureVersion")
            payload = self._notification()
            payload['SignatureVersion'] = '3'
            self.assertFalse(verify_bounce_message(payload))

            print("  → Version 1 signature labelled as version 2")
            payload = self._notification(version='1')
            payload['SignatureVersion'] = '2'
            self.assertFalse(verify_bounce_message(payload))
        print("  ✓ Invalid signatures rejected")

    def test_untrusted_cert_urls_rejected(self):
        """Test certificates outside sns.<region>.amazonaws.com are never downloaded - expects rejection"""
        print("\n⚠ Testing untrusted SigningCertURLs (expecting rejection, no download)")
        untrusted = [
            ('S3 bucket on amazonaws.com', 'https://attacker.s3.amazonaws.com/cert.pem'),
            ('plain http', 'http://sns.us-east-1.amazonaws.com/cert.pem'),
            ('not a .pem path', 'https://sns.us-east-1.amazonaws.com/cert.txt'),
            ('user-info trick', 'https://sns.us-east-1.amazonaws.com@evil.example.com/cert.pem'),
            ('look-alike host', 'https://sns.us-east-1.amazonaws.com.evil.example.com/cert.pem'),
            ('other domain', 'https://evil.example.com/cert.pem'),
        ]
        with patch('requests.get', return_value=_cert_response(self.pem)) as mock_get:
            for label, url in untrusted:
                print(f"  → {label}")
                self.assertFalse(verify_bounce_message(self._notification(SigningCertURL=url)), label)
            mock_get.assert_not_called()

        print("  → China region host is accepted")
        with patch('requests.get', return_value=_cert_response(self.pem)):
            cn_url = 'https://sns.cn-north-1.amazonaws.com.cn/SimpleNotificationService-test.pem'
            with patch.object(aws_ses_settings, 'BOUNCE_CERT_DOMAINS', ('amazonaws.com.cn',)):
                self.assertTrue(verify_bounce_message(self._notification(SigningCertURL=cn_url)))
        print("  ✓ Only SNS-hosted certificates are trusted")

    def test_topic_arn_allowlist(self):
        """Test AWS_SES_BOUNCE_TOPIC_ARNS rejects other topics - expects rejection"""
        print("\n⚠ Testing TopicArn allowlist (expecting rejection for other topics)")
        with patch('requests.get', return_value=_cert_response(self.pem)), \
                patch.object(aws_ses_settings, 'BOUNCE_TOPIC_ARNS', (SNS_TOPIC_ARN,)):
            print("  → Configured topic accepted")
            self.assertTrue(verify_bounce_message(self._notification()))
            print("  → Validly signed message from another topic rejected")
            self.assertFalse(verify_bounce_message(self._notification(topic_arn=OTHER_TOPIC_ARN)))
        print("  → Empty allowlist accepts any topic")
        with patch('requests.get', return_value=_cert_response(self.pem)), \
                patch.object(aws_ses_settings, 'BOUNCE_TOPIC_ARNS', ()):
            self.assertTrue(verify_bounce_message(self._notification(topic_arn=OTHER_TOPIC_ARN)))
        print("  ✓ TopicArn allowlist enforced")

    def test_certificate_cached_and_fetched_with_timeout(self):
        """Test the signing certificate is downloaded once, with a timeout"""
        print("\n✓ Testing certificate caching and download timeout")
        with patch('requests.get', return_value=_cert_response(self.pem)) as mock_get:
            print("  → Verifying two messages signed by the same certificate")
            self.assertTrue(verify_bounce_message(self._notification()))
            self.assertTrue(verify_bounce_message(self._notification(event='Complaint')))
        print("  → Certificate downloaded once, with a timeout")
        mock_get.assert_called_once_with(SNS_CERT_URL, timeout=aws_ses_utils.SNS_REQUEST_TIMEOUT)

    def test_certificate_download_failure_rejected(self):
        """Test a failed certificate download - expects rejection, not an exception"""
        print("\n⚠ Testing certificate download failures (expecting rejection)")
        print("  → Download times out")
        with patch('requests.get', side_effect=requests.Timeout('timed out')):
            self.assertFalse(verify_bounce_message(self._notification()))
        print("  → Download returns 404")
        not_found = Mock(status_code=404, content=b'')
        with patch('requests.get', return_value=not_found):
            self.assertFalse(verify_bounce_message(self._notification()))
        print("  → Failed downloads are not cached")
        with patch('requests.get', return_value=_cert_response(self.pem)):
            self.assertTrue(verify_bounce_message(self._notification()))
        print("  ✓ Download failures handled")

    def test_endpoint_records_only_verified_notifications(self):
        """Test the bounce endpoint stores verified notifications and drops others"""
        print("\n✓ Testing bounce endpoint with real signatures")
        with patch('requests.get', return_value=_cert_response(self.pem)), \
                patch.object(aws_ses_settings, 'BOUNCE_TOPIC_ARNS', (SNS_TOPIC_ARN,)):
            print("  → Signed bounce and complaint from the configured topic")
            self.assertEqual(self._post(self._notification()).status_code, 200)
            self.assertEqual(self._post(self._notification(event='Complaint')).status_code, 200)
            self.assertTrue(BounceRecord.objects.filter(email='bounced@example.com').exists())
            self.assertTrue(ComplaintRecord.objects.filter(email='complained@example.com').exists())

            print("  → Signed complaint from another topic (200, nothing stored)")
            BounceRecord.objects.all().delete()
            ComplaintRecord.objects.all().delete()
            response = self._post(self._notification(event='Complaint', topic_arn=OTHER_TOPIC_ARN))
            self.assertEqual(response.status_code, 200)
            self.assertFalse(ComplaintRecord.objects.exists())

            print("  → Tampered bounce (200, nothing stored)")
            payload = self._notification()
            payload['Message'] = payload['Message'].replace('bounced@', 'victim@')
            self.assertEqual(self._post(payload).status_code, 200)
            self.assertFalse(BounceRecord.objects.exists())
        print("  → Only verified notifications recorded")

    def test_subscription_confirmation(self):
        """Test subscriptions are confirmed only for configured topics and SNS URLs"""
        print("\n⚠ Testing subscription confirmation (expecting unknown topics to be ignored)")
        with patch('requests.get', return_value=_cert_response(self.pem)) as mock_get, \
                patch.object(aws_ses_settings, 'BOUNCE_TOPIC_ARNS', (SNS_TOPIC_ARN,)):
            print("  → Subscription from another topic is not confirmed")
            self.assertEqual(self._post(self._subscription(topic_arn=OTHER_TOPIC_ARN)).status_code, 200)
            self.assertNotIn(SNS_SUBSCRIBE_URL, [c.args[0] for c in mock_get.call_args_list])

            print("  → Subscription from the configured topic is confirmed, with a timeout")
            self.assertEqual(self._post(self._subscription()).status_code, 200)
            mock_get.assert_any_call(SNS_SUBSCRIBE_URL, timeout=aws_ses_utils.SNS_REQUEST_TIMEOUT)

        print("  → SubscribeURL off SNS is never requested, even with verification off")
        evil_url = 'https://evil.example.com/confirm'
        with patch('requests.get') as mock_get, \
                patch.object(aws_ses_settings, 'VERIFY_BOUNCE_SIGNATURES', False):
            self.assertEqual(self._post(self._subscription(subscribe_url=evil_url)).status_code, 200)
            mock_get.assert_not_called()
        print("  ✓ Subscription confirmation restricted")

    def test_unsubscribe_confirmation_not_resubscribed(self):
        """Test an UnsubscribeConfirmation is acknowledged without re-subscribing"""
        print("\n✓ Testing UnsubscribeConfirmation does not re-subscribe the endpoint")
        with patch('requests.get', return_value=_cert_response(self.pem)) as mock_get, \
                patch.object(aws_ses_settings, 'BOUNCE_TOPIC_ARNS', (SNS_TOPIC_ARN,)):
            print("  → Posting a signed UnsubscribeConfirmation from the configured topic")
            payload = self._subscription(message_type='UnsubscribeConfirmation')
            self.assertEqual(self._post(payload).status_code, 200)
            print("  → Message verified (certificate fetched) but SubscribeURL never requested")
            mock_get.assert_called_once_with(SNS_CERT_URL, timeout=aws_ses_utils.SNS_REQUEST_TIMEOUT)
        print("  → Unsubscribe left in place")