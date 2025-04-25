# django_aws_ses

A Django email backend for Amazon Simple Email Service (SES), featuring bounce and complaint handling, unsubscribe functionality, and robust integration with Django’s email system. Developed by ZeeksGeeks.

## Features

- Seamless integration with Django’s email framework using a custom SES backend.
- Handles AWS SES bounce and complaint notifications via SNS.
- Secure unsubscribe functionality.
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
    'django_aws_ses',
]

SITE_ID = 1
```

Configure AWS SES credentials and the email backend:

```python
AWS_SES_ACCESS_KEY_ID = 'your-access-key-id'  # Replace with your AWS IAM credentials
AWS_SES_SECRET_ACCESS_KEY = 'your-secret-access-key'
AWS_SES_REGION_NAME = 'us-east-1'  # Adjust to your AWS SES region
AWS_SES_REGION_ENDPOINT = 'https://email.us-east-1.amazonaws.com'

EMAIL_BACKEND = 'django_aws_ses.backends.SESBackend'
DEFAULT_FROM_EMAIL = 'no-reply@yourdomain.com'  # Verified in AWS SES
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

This enables endpoints for bounce/complaint handling (`https://yourdomain.com/aws_ses/bounce/`) and unsubscribe functionality (`https://yourdomain.com/aws_ses/unsubscribe/<uuid>/<token>/`).

### Step 4: Apply Migrations

Run migrations to create the `django_aws_ses` models (e.g., `AwsSesSettings`, `BounceRecord`, `ComplaintRecord`, `SendRecord`, `AwsSesUserAddon`):

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

- Users clicking the link are redirected to `/aws_ses/unsubscribe/<uuid>/<token>/`, which marks them as unsubscribed.
- Customize the unsubscribe view or template in `django_aws_ses/templates/django_aws_ses/unsubscribe.html`.

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