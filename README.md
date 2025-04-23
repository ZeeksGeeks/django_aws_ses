# django_aws_ses

A Django email backend for Amazon Simple Email Service (SES), featuring bounce and complaint handling, unsubscribe functionality, and robust integration with Django’s email system. Developed by ZeeksGeeks.

## Features
- Seamless integration with Django’s email framework using a custom SES backend.
- Handles AWS SES bounce and complaint notifications via SNS.
- Secure unsubscriptions fuctionality.
- Django Admin dashboard for SES statistics.
- (Optional) Supports DKIM signing, requires `dkimpy`.

## Installation

Follow these steps to install and configure `django_aws_ses` in your Django project.

### Prerequisites
- Python 3.6 or higher
- Django 3.2 or higher
- An AWS account with SES access
- Verified email address or domain in AWS SES

### Step 1: Install the Package
Install `django_aws_ses` from TestPyPI (or PyPI once published):

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ django_aws_ses
```

For production, this installs the core dependencies:
- `django>=3.2`
- `boto3>=1.18.0`
- `requests>=2.26.0`
- `cryptography>=3.4.7`
- `dnspython>=2.1.0`

For development or testing, include development dependencies:
```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ django_aws_ses[dev]
```

For DKIM signing support (optional):
```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ django_aws_ses[dkim]
```

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
AWS_SES_REGION_ENDPOINT = 'email.us-east-1.amazonaws.com'

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

This enables endpoints for bounce/complaint handling (`/aws_ses/bounce/`) and unsubscribe functionality (`/aws_ses/unsubscribe/<uuid>/<token>/`).

### Step 4: Apply Migrations
Run migrations to create the `django_aws_ses` models (e.g., `AwsSesSettings`, `BounceRecord`):

```bash
python manage.py migrate
```

### Step 5: Configure AWS SES
- **Verify Email/Domain**: In the AWS SES console, verify your sender email (e.g., `no-reply@yourdomain.com`) or domain.
- **SNS Notifications**: Set up an SNS topic to send bounce and complaint notifications to your `/aws_ses/bounce/` endpoint.
- **Exit Sandbox Mode** (if needed): Request production access in AWS SES to send emails to unverified recipients.
- **IAM Permissions**: Ensure your IAM user has permissions for SES (e.g., `AmazonSESFullAccess`) and SNS if using notifications.

## Usage
Send an email using Django’s email API:

```python
from django.core.mail import send_mail

send_mail(
    subject='Test Email',
    message='This is a test email from django_aws_ses.',
    from_email='no-reply@yourdomain.com',
    recipient_list=['recipient@example.com'],
    fail_silently=False,
)
```

Generate an unsubscribe link for a user:

```python
from django_aws_ses.models import AwsSesUserAddon

user = User.objects.get(email='recipient@example.com')
addon = AwsSesUserAddon.objects.get(user=user)
unsubscribe_url = addon.unsubscribe_url_generator()
# Include unsubscribe_url in your email template
```

View SES statistics (superusers only) at `/aws_ses/status/`.

## Contributors
Developed by the ZeeksGeeks team. See [CONTRIBUTORS.md](CONTRIBUTORS.md) for individual contributors and their roles.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.