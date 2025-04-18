# Django AWS SES

A Django email backend for sending emails via Amazon Simple Email Service (SES).

## Features
- Send emails using AWS SES with DKIM signing support.
- Handle bounce, complaint, and delivery notifications via SNS webhooks.
- Filter recipients based on bounce/complaint history and domain validation.
- Admin dashboard for SES statistics and verified emails.
- Unsubscribe functionality with secure URL generation.

## Installation
```bash
pip install django_aws_ses
```

## Requirements
- Python 3.8+
- Django 3.2+
- AWS SES account with verified domains/emails

## Setup
1. Add to `INSTALLED_APPS`:
   ```python
   INSTALLED_APPS = [
       ...
       'django_aws_ses',
   ]
   ```

2. Configure settings in `settings.py`:
   ```python
   AWS_SES_ACCESS_KEY_ID = 'your-access-key'
   AWS_SES_SECRET_ACCESS_KEY = 'your-secret-key'
   AWS_SES_REGION_NAME = 'us-east-1'
   AWS_SES_REGION_ENDPOINT = 'email.us-east-1.amazonaws.com'
   EMAIL_BACKEND = 'django_aws_ses.backends.SESBackend'
   ```

3. Apply migrations:
   ```bash
   python manage.py migrate
   ```

4. (Optional) Enable DKIM signing:
   ```python
   DKIM_DOMAIN = 'example.com'
   DKIM_PRIVATE_KEY = 'your-private-key'
   DKIM_SELECTOR = 'ses'
   ```

5. Set up SNS webhook for bounce/complaint handling:
   - Add the URL `your-domain.com/aws_ses/bounce/` to your SNS subscription.
   - Ensure the view is accessible (e.g., CSRF-exempt).

## Usage
- Send emails using Django’s `send_mail` or `EmailMessage`.
- View SES statistics at `/aws_ses/status/` (superuser only).
- Unsubscribe users via `/aws_ses/unsubscribe/<uuid>/<hash>/`.

## Development
To contribute:
1. Clone the repo: `git clone https://github.com/zeeksgeeks/django_aws_ses`
2. Install dependencies: `pip install -r requirements.txt`
3. Run tests: `python manage.py test`

## License
MIT License. See [LICENSE](LICENSE) for details.

## Credits
Developed by Ray Jessop. Inspired by [django-ses](https://github.com/django-ses/django-ses).