# django_aws_ses

A Django email backend for Amazon Simple Email Service (SES), featuring bounce and complaint handling, unsubscribe functionality, and robust integration with Django’s email system. Developed by ZeeksGeeks.

## Features

- Seamless integration with Django’s email framework using a custom SES backend.
- Handles AWS SES bounce and complaint notifications via SNS.
- Secure unsubscribe functionality, including RFC 8058 one-click unsubscribe and a JSON API for custom frontends.
- Django Admin dashboard for SES statistics (superusers only).
- Optional DKIM signing support (requires `dkimpy`).

## Installation

Follow these steps to install and configure `django_aws_ses` in your Django project.

### Prerequisites

- Python 3.6 or higher
- Django 3.2 or higher
- An AWS account with SES access
- Verified email address or domain in AWS SES

### Step 1: Install the Package

Install `django_aws_ses` from PyPI:

```bash
pip install django-aws-ses
```

For development or testing, include development dependencies:

```bash
pip install django-aws-ses[dev]
```

For DKIM signing support (optional):

```bash
pip install django-aws-ses[dkim]
```

This installs core dependencies:

- `django>=3.2`
- `boto3>=1.18.0`
- `requests>=2.26.0`
- `cryptography>=3.4.7`
- `dnspython>=2.1.0`

### Step 2: Configure Django Settings

Add `django_aws_ses` and required Django apps to `INSTALLED_APPS` in your `settings.py`:

```python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
]

```

	Configure AWS SES credentials and the email backend:
### Option 1: IAM Role (Recommended for AWS environments)
```python
# No AWS credentials needed in settings
AWS_SES_REGION_NAME = 'us-east-1'
AWS_SES_REGION_ENDPOINT = 'https://email.us-east-1.amazonaws.com'
EMAIL_BACKEND = 'django_aws_ses.backends.SESBackend'
DEFAULT_FROM_EMAIL = 'no-reply@yourdomain.com'
```
### Option 2: Access Keys
```
AWS_SES_ACCESS_KEY_ID = 'your-access-key-id'
AWS_SES_SECRET_ACCESS_KEY = 'your-secret-access-key'
```

Optional: Enable debugging logs for troubleshooting:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django_aws_ses': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
```

### Step 3: Set Up URLs

Include the `django_aws_ses` URLs in your project’s `urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    path('aws_ses/', include('django_aws_ses.urls', namespace='django_aws_ses')),
]
```

This enables endpoints for:

- Bounce/complaint handling: `https://yourdomain.com/aws_ses/bounce/`
- Unsubscribe confirmation page: `https://yourdomain.com/aws_ses/unsubscribe/token/<token>/`
- RFC 8058 one-click unsubscribe: `https://yourdomain.com/aws_ses/unsubscribe/one-click/<token>/`
- JSON unsubscribe API: `https://yourdomain.com/aws_ses/unsubscribe/api/<token>/`
- Legacy routes kept for links in emails already sent: `unsubscribe/<uuid>/<token>/` and `unsubscribe/email/<encoded_email>/<token>/`

### Step 4: Apply Migrations

Run migrations to create the `django_aws_ses` models (e.g., `BounceRecord`, `ComplaintRecord`, `SendRecord`, `AwsSesUserAddon`):

```bash
python manage.py migrate
```

### Step 5: Configure AWS SES

Follow these detailed steps to set up Amazon SES in your AWS account for use with `django_aws_ses`:

1. **Sign Up for AWS SES**:

   - Log in to the AWS Management Console.
   - Navigate to SES: https://console.aws.amazon.com/ses/.
   - If new to SES, follow prompts to activate the service.
   - Docs: https://docs.aws.amazon.com/ses/latest/dg/get-set-up.html

2. **Verify Sender Email or Domain**:

   - In the SES console, go to "Verified identities."
   - Click "Create identity":
     - **Email Address**: Enter the sender email (e.g., `no-reply@yourdomain.com`). AWS sends a verification email; click the link to verify.
     - **Domain**: Enter your domain (e.g., `yourdomain.com`). Add provided DNS records (TXT, CNAME, MX) to your DNS provider to verify ownership.
   - Docs: https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html

3. **Create IAM Credentials**:

   - Create an IAM user for SES:
     - Go to IAM in AWS Console: https://console.aws.amazon.com/iam/.
     - Create a user (e.g., `ses-user`) with programmatic access.
     - Attach permissions (e.g., `AmazonSESFullAccess` and `AmazonSNSFullAccess`).
     - Save the Access Key ID and Secret Access Key for `settings.py`.
   - Docs: https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html

4. **Set Up SNS Notifications**:

   - Create an SNS topic (e.g., `SES_Notifications`) in the SNS console: https://console.aws.amazon.com/sns/.
   - Subscribe your bounce/complaint endpoint (`https://yourdomain.com/aws_ses/bounce/`) to the topic using the HTTPS protocol.
   - In SES, go to "Verified identities," select your email/domain, and configure notifications to send bounces, complaints, and deliveries to the SNS topic.
   - Docs: https://docs.aws.amazon.com/ses/latest/dg/monitor-using-notifications.html

5. **(Optional) Configure DKIM Signing**:

   - If using DKIM, enable it in SES:
     - In "Verified identities," select your domain and enable DKIM.
     - Add provided DNS records to your DNS provider.
   - Ensure `dkimpy` is installed (`pip install django-aws-ses[dkim]`).
   - Docs: https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim.html

6. **Test SES Configuration**:

   - In SES console, send a test email from "Verified identities."
   - Verify receipt in the recipient’s inbox.
   - Test sending from Django (see Usage).
   - Docs: https://docs.aws.amazon.com/ses/latest/dg/send-an-email.html

7. **Exit Sandbox Mode (Production)**:

   - SES sandbox mode restricts sending to verified emails only.
   - For production, request access:
     - Open a support case in AWS Support Center.
     - Provide use case (e.g., transactional emails for user registration).
     - Approval typically takes 24 hours.
   - Docs: https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html

## Usage

`django_aws_ses` integrates with Django’s email API and provides additional features for SES-specific functionality. The following examples are shown in a Python console (e.g., Django shell or within a view).

### Sending a Basic Email

Use Django’s `send_mail` for simple emails:

```python
from django.core.mail import send_mail

send_mail(
    subject='Test Email',
    message='This is a test email from django_aws_ses.',
    from_email='no-reply@yourdomain.com',  # Must be SES-verified
    recipient_list=['recipient@example.com'],
    fail_silently=False,
)
```

- Set `fail_silently=False` to raise exceptions for debugging (e.g., unverified email errors).

### Sending HTML Emails

Send emails with HTML content and plain text fallback:

```python
from django.core.mail import EmailMultiAlternatives

subject = 'Welcome to Our Platform'
from_email = 'no-reply@yourdomain.com'
to = 'recipient@example.com'
text_content = 'Thank you for joining our platform!'
html_content = '<p>Thank you for joining! <a href="https://yourdomain.com">Visit us</a></p>'

email = EmailMultiAlternatives(subject, text_content, from_email, [to])
email.attach_alternative(html_content, 'text/html')
email.send()
```

### Sending Email Attachments

Send emails with attachments using `EmailMultiAlternatives`:

```python
from django.core.mail import EmailMultiAlternatives

subject = 'Document from Our Platform'
from_email = 'no-reply@yourdomain.com'
to = 'recipient@example.com'
text_content = 'Please find the attached document.'

email = EmailMultiAlternatives(subject, text_content, from_email, [to])
email.attach('document.pdf', open('path/to/document.pdf', 'rb').read(), 'application/pdf')
email.send()
```

- **Note**: Amazon SES limits the total email size, including attachments, to 10MB. Ensure attachments are within this limit to avoid delivery failures.

### Handling Bounce and Complaint Notifications

- Bounce and complaint notifications are processed via the SNS endpoint (`/aws_ses/bounce/`).
- Records are stored in the `BounceRecord` and `ComplaintRecord` models.
- View bounce/complaint data in the Django Admin or SES dashboard (`/aws_ses/status/`).
- Configure additional SNS notifications for deliveries in SES console.
- Docs: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html

### Generating Unsubscribe Links

Add secure unsubscribe links to emails:

```python
from django_aws_ses.models import AwsSesUserAddon

user = User.objects.get(email='recipient@example.com')
addon = AwsSesUserAddon.objects.get_or_create(user=user)[0]
unsubscribe_url = addon.unsubscribe_url_generator()
# Include in email template, e.g., <a href="{{ unsubscribe_url }}">Unsubscribe</a>
```

- By default the link points to `/aws_ses/unsubscribe/token/<token>/`, a confirmation page with Unsubscribe / Re-subscribe buttons. Opening the link (GET) never changes anything; only submitting the form (POST) does. The page shows the address masked (e.g. `a***@example.com`), as do the older uuid and encoded-email pages, so a forwarded link does not reveal it.
- `unsubscribe_url_generator()` returns a relative path; prefix your site's origin when putting it in an email, or set `AWS_SES_UNSUBSCRIBE_URL` (see below).
- The token contains only the record id, signed with your `SECRET_KEY`. The email address is not in the link, so it is not exposed when an email is forwarded.
- Links generated by 0.1.6 and earlier (which embedded the address) keep working. Set `AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS = False` to stop accepting them.
- Customize the unsubscribe view or template in `django_aws_ses/templates/django_aws_ses/unsubscribe.html`. Custom templates must keep `{% csrf_token %}` inside the form.

### Generating Unsubscribe Links for Non-User Emails

For mailing lists or launch notifications where recipients may not have accounts, use `EmailUnsubscribe`:

```python
from django_aws_ses.models import EmailUnsubscribe

emails = ['recipient@example.com', 'other@example.com']

# Bulk get-or-create unsubscribe records
existing = {u.email: u for u in EmailUnsubscribe.objects.filter(email__in=emails)}
to_create = [EmailUnsubscribe(email=e) for e in emails if e not in existing]
if to_create:
    EmailUnsubscribe.objects.bulk_create(to_create, ignore_conflicts=True)
    all_unsubs = {u.email: u for u in EmailUnsubscribe.objects.filter(email__in=emails)}
else:
    all_unsubs = existing

for email in emails:
    unsub = all_unsubs.get(email)
    if unsub and unsub.unsubscribed:
        continue
    unsubscribe_url = unsub.unsubscribe_url_generator()
    # append unsubscribe_url to the email body before sending
```

- Links point to `/aws_ses/unsubscribe/token/<token>/` and are self-authenticating — no session or login required. The address is not in the URL.
- Run `python manage.py migrate django_aws_ses` after upgrading to create the `EmailUnsubscribe` table.
- By default the backend does **not** block addresses whose `EmailUnsubscribe` record is unsubscribed; skip them yourself as above, or set `AWS_SES_FILTER_EMAIL_UNSUBSCRIBES = True` to have the backend drop them. With `AWS_SES_AUTO_LIST_UNSUBSCRIBE = True` the backend always drops them, because it sends one-click headers for these records.

### Unsubscribe Settings

| Setting | Default | Purpose |
|---|---|---|
| `AWS_SES_UNSUBSCRIBE_URL` | `None` | Where unsubscribe links point. A string containing `{token}` (e.g. `'https://app.example.com/unsubscribe/{token}'`) or a callable taking the token. In the string form the token is percent-encoded and any other `{...}` is left as is; a callable receives the raw token and must encode it itself. `None` uses the library's confirmation page. |
| `AWS_SES_UNSUBSCRIBE_BASE_URL` | `None` | Absolute HTTPS origin of this Django backend (e.g. `'https://api.example.com'`). Required for one-click unsubscribe; it is never guessed. |
| `AWS_SES_AUTO_LIST_UNSUBSCRIBE` | `False` | Add one-click headers automatically (see below). Requires `AWS_SES_UNSUBSCRIBE_BASE_URL`; the backend raises `ImproperlyConfigured` when it is created if that is missing. Also turns on the `EmailUnsubscribe` filter. |
| `AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS` | `True` | Accept tokens from links generated by 0.1.6 and earlier. |
| `AWS_SES_FILTER_EMAIL_UNSUBSCRIBES` | `False` | Also drop recipients whose `EmailUnsubscribe` record is unsubscribed. Always on when `AWS_SES_AUTO_LIST_UNSUBSCRIBE` is `True`. |

### Hosting the Unsubscribe Page in Your Own Frontend

Set `AWS_SES_UNSUBSCRIBE_URL` so generated links open your frontend, then have the page call the JSON API with the token from its URL:

```
GET  /aws_ses/unsubscribe/api/<token>/
     -> {"kind": "user", "unsubscribed": false, "email": "t***@example.com"}

POST /aws_ses/unsubscribe/api/<token>/   body: {"unsubscribed": true}
     -> {"kind": "user", "unsubscribed": true, "email": "t***@example.com"}
```

- Invalid tokens return 404; bad bodies return 400. GET never changes state.
- No session, login or CSRF token is needed: the signed token is the credential. Configure CORS yourself if the frontend is on another origin.
- The email is masked in responses so a forwarded link does not reveal the full address.

The same operations are available as plain Python helpers if you prefer to write your own endpoints (e.g. with DRF):

```python
from django_aws_ses import unsubscribe

record = unsubscribe.resolve_token(token)      # AwsSesUserAddon, EmailUnsubscribe, or None
unsubscribe.get_status(record)                 # {'kind', 'unsubscribed', 'email' (masked)}
unsubscribe.set_unsubscribed(record, True)     # or False to re-subscribe
```

### One-Click Unsubscribe (RFC 8058)

Gmail and Yahoo require bulk senders to support one-click unsubscribe, and show their own Unsubscribe button when the message carries these headers:

```
List-Unsubscribe: <https://api.example.com/aws_ses/unsubscribe/one-click/<token>/>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```

Setup:

1. Set `AWS_SES_UNSUBSCRIBE_BASE_URL = 'https://api.example.com'` (the public HTTPS origin serving the `aws_ses/` URLs).
2. Add the headers per message:

   ```python
   from django.core.mail import EmailMultiAlternatives

   email = EmailMultiAlternatives(subject, text, from_email, [user.email],
                                  headers=user.aws_ses.list_unsubscribe_headers())
   # or EmailUnsubscribe.list_unsubscribe_headers(), or
   # django_aws_ses.unsubscribe.list_unsubscribe_headers(user_or_record)
   ```

   **If you add headers by hand for `EmailUnsubscribe` records, set `AWS_SES_FILTER_EMAIL_UNSUBSCRIBES = True`** (or skip unsubscribed records yourself). Otherwise a one-click unsubscribe is recorded but the address keeps receiving mail, which breaks RFC 8058 and the Gmail/Yahoo bulk-sender rules. User records are always filtered.

   Or set `AWS_SES_AUTO_LIST_UNSUBSCRIBE = True` and the backend adds them to messages with exactly **one** recipient (to + cc + bcc) that maps to a user or `EmailUnsubscribe` record. Tokens are per recipient, so multi-recipient messages are skipped, as are messages that already set `List-Unsubscribe` and transactional messages. This setting also makes the backend honour `EmailUnsubscribe` unsubscribes.

The one-click endpoint unsubscribes only on a `POST` whose form body is exactly `List-Unsubscribe=One-Click`; any other POST returns 400 without changing anything, and methods other than GET/POST return 405.

**Why GET never unsubscribes:** link scanners such as Outlook/Microsoft Defender Safe Links and corporate mail gateways fetch every URL in incoming mail. If a GET could unsubscribe, recipients would be unsubscribed without ever clicking. A GET on the one-click URL (some mail clients open it in a browser instead of POSTing) redirects to the confirmation page instead, or to `HOME_URL` if the token is not validly signed. Keep this rule in any custom unsubscribe page you build.

**DKIM must cover the List-Unsubscribe headers:** Gmail and Yahoo only honour one-click when `List-Unsubscribe` and `List-Unsubscribe-Post` are covered by a valid DKIM signature. SES Easy DKIM signs them. With library-side signing (the `DKIM_*` settings and `dkimpy`), the backend adds both headers to its signed header list whenever they are present.

**Long headers on Django 6:** Django 6 builds messages with `email.policy.default`, which RFC 2047-encodes header values longer than 78 characters that cannot be folded, such as a long URL. Mail clients do not accept an encoded URL. The backend builds messages with a 998-character line limit (the SMTP maximum), so the header stays on one plain line on every supported Django version. ASCII bodies with lines longer than 78 characters are now sent as `7bit` instead of `quoted-printable`; other bodies are unchanged.

### Transactional Messages

Password resets and verification codes should reach users even after they unsubscribe from other mail. Mark such a message to skip only the unsubscribe filter; complaint, bounce and domain filters still apply:

```python
email = EmailMultiAlternatives(subject, text, from_email, [user.email])
email.aws_ses_transactional = True
# or: headers={'X-Django-AWS-SES-Transactional': '1'}   (removed before sending)
email.send()
```

### Recipient Filtering

Before sending, the backend drops recipients who have unsubscribed, have a complaint record, have at least `SES_BOUNCE_LIMIT` bounce records, or whose domain is blacklisted or has no MX record. The dropped addresses are returned in the `Sent` entry of `send_messages()`'s result.

- Addresses are compared case-insensitively. On SQLite this only covers ASCII letters (SQLite's `LOWER()` leaves letters such as `Ü` unchanged), so an address that differs only in the case of a non-ASCII letter will not match. PostgreSQL and MySQL handle these correctly.
- Recipients written as `"Name <user@example.com>"` are matched on the address part, and the original string is kept in the message.
- Bounces are counted per address, so `SES_BOUNCE_LIMIT = 3` drops an address after its third bounce.

### Viewing SES Statistics

- Access the SES dashboard at `/aws_ses/status/` (superusers only).
- Displays bounce rates, complaint rates, and email sending history.
- Uses `BounceRecord`, `ComplaintRecord`, and `SendRecord` models for metrics.
- Docs: https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-metrics.html

### Debugging and Error Handling

- Enable debug logging (see Step 2) to troubleshoot SES errors.
- Common issues:
  - **Unverified email/domain**: Verify in SES console.
  - **IAM permissions**: Ensure `AmazonSESFullAccess` and `AmazonSNSFullAccess`.
  - **SNS endpoint errors**: Confirm HTTPS endpoint is publicly accessible.
- Check `BounceRecord` and `ComplaintRecord` in Django Admin for failed deliveries.

### Rate Limiting and Throttling

- SES imposes sending quotas and rate limits.
- Monitor limits in SES console ("Sending Statistics").
- If approaching limits, request a quota increase:
  - Open a support case in AWS Support Center.
  - Specify desired sending rate and daily quota.
- Docs: https://docs.aws.amazon.com/ses/latest/dg/manage-sending-limits.html

## Changelog

For a detailed list of changes, improvements, and fixes across versions, see [CHANGELOG.md](https://github.com/zeeksgeeks/django_aws_ses/blob/master/CHANGELOG.md).

## Contributors

Developed by the ZeeksGeeks team. See [CONTRIBUTORS.md](https://github.com/zeeksgeeks/django_aws_ses/blob/master/CONTRIBUTORS.md) for individual contributors and their roles.

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository: https://github.com/zeeksgeeks/django_aws_ses
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m 'Add your feature'`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request.

See [CONTRIBUTORS.md](https://github.com/zeeksgeeks/django_aws_ses/blob/master/CONTRIBUTORS.md) for current contributors.

## License

This project is licensed under the MIT License. See [LICENSE](https://github.com/zeeksgeeks/django_aws_ses/blob/master/LICENSE) for details.

## PyPI Distribution

- Install: `pip install django-aws-ses`
- Source: https://github.com/zeeksgeeks/django_aws_ses
- Issues: https://github.com/zeeksgeeks/django_aws_ses/issues
- PyPI: https://pypi.org/project/django-aws-ses/
- TestPyPI: https://test.pypi.org/project/django-aws-ses/
- Changelog: See [CHANGELOG.md](https://github.com/zeeksgeeks/django_aws_ses/blob/master/CHANGELOG.md) for version history.