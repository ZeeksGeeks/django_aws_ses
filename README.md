# Django AWS SES

*(Badge to be activated upon PyPI release)*

A Django email backend for sending emails via Amazon Simple Email Service (SES).

## Features

- Send emails using AWS SES with optional DKIM signing.
- Handle bounce, complaint, and delivery notifications via SNS webhooks.
- Filter recipients based on bounce/complaint history and domain validation.
- Admin dashboard for SES statistics and verified emails.
- Secure unsubscribe functionality with confirmation step.

## Installation

```bash
pip install django_aws_ses
```

## Requirements

- Python 3.8+
- Django 3.2+
- AWS SES account with verified domains/emails

## Quick Start

1. Install the package:

   ```bash
   pip install django_aws_ses
   ```

2. Add to `INSTALLED_APPS` in `settings.py`:

   ```python
   INSTALLED_APPS = [
       ...
       'django_aws_ses',
   ]
   ```

3. Configure AWS SES settings in `settings.py`:

   ```python
   AWS_SES_ACCESS_KEY_ID = 'your-access-key'
   AWS_SES_SECRET_ACCESS_KEY = 'your-secret-key'
   AWS_SES_REGION_NAME = 'us-east-1'
   AWS_SES_REGION_ENDPOINT = 'email.us-east-1.amazonaws.com'
   EMAIL_BACKEND = 'django_aws_ses.backends.SESBackend'
   ```

4. Apply migrations:

   ```bash
   python manage.py migrate
   ```

5. Test email sending:

   ```python
   from django.core.mail import send_mail
   send_mail('Subject', 'Message', 'from@example.com', ['to@example.com'])
   ```

## Advanced Setup

### DKIM Signing (Optional)

To enable DKIM for email authentication:

1. Generate a DKIM key pair and configure in AWS SES.
2. Add to `settings.py`:

   ```python
   DKIM_DOMAIN = 'example.com'
   DKIM_PRIVATE_KEY = 'your-private-key'
   DKIM_SELECTOR = 'ses'
   ```

### SNS Webhook for Notifications

To handle bounces, complaints, and deliveries:

1. Set up an SNS topic in AWS and subscribe the URL `your-domain.com/aws_ses/bounce/`.
2. Ensure the view is publicly accessible and CSRF-exempt (configured by default).

### Unsubscribe Functionality

- Users receive a secure unsubscribe link (`/aws_ses/unsubscribe/<uuid>/<hash>/`).
- A confirmation page prevents accidental unsubscribes (e.g., by email scanners).
- Re-subscribe option available on the same page.

## Usage

- **Send Emails**: Use Django’s `send_mail` or `EmailMessage` as usual.
- **View Statistics**: Access `/aws_ses/status/` (superuser only) for SES quotas and sending stats.
- **Manage Unsubscribes**: Users can unsubscribe or re-subscribe via the secure link.

## Development

### Running Tests

1. Install test dependencies:

   ```bash
   pip install -r requirements-dev.txt
   ```

2. Run tests:

   ```bash
   python manage.py test django_aws_ses
   ```

### Contributing

1. Clone the repo:

   ```bash
   git clone https://git-vault.zeeksgeeks.com/zeeksgeeks/django_aws_ses
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create a feature branch and submit a pull request.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Credits

Developed by Ray Jessop. Inspired by [django-ses](https://github.com/django-ses/django-ses).