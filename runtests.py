#!/usr/bin/env python
"""Run the django_aws_ses test suite without a host Django project.

Usage:
    python runtests.py                                   # whole suite
    python runtests.py django_aws_ses.tests.OneClickUnsubscribeTests
"""
import os
import sys

import django
from django.conf import settings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def main(labels):
    # Test output uses ✓/⚠; Windows consoles default to cp1252, which cannot print them.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    sys.path.insert(0, BASE_DIR)
    if not settings.configured:
        settings.configure(
            BASE_DIR=BASE_DIR,
            SECRET_KEY='django_aws_ses-tests-not-secret',
            DEBUG=False,
            TESTING=True,
            TIME_ZONE='UTC',
            USE_TZ=True,
            ALLOWED_HOSTS=['testserver'],
            DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
            INSTALLED_APPS=[
                'django.contrib.auth',
                'django.contrib.contenttypes',
                'django.contrib.sessions',
                'django_aws_ses',
            ],
            MIDDLEWARE=[
                'django.contrib.sessions.middleware.SessionMiddleware',
                'django.middleware.common.CommonMiddleware',
                'django.middleware.csrf.CsrfViewMiddleware',
                'django.contrib.auth.middleware.AuthenticationMiddleware',
            ],
            ROOT_URLCONF='test_urls',
            TEMPLATES=[{
                'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'APP_DIRS': True,
                'OPTIONS': {'context_processors': [
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                ]},
            }],
            STATIC_URL='/static/',
            EMAIL_BACKEND='django_aws_ses.backends.SESBackend',
            PASSWORD_HASHERS=['django.contrib.auth.hashers.MD5PasswordHasher'],
            DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        )
    django.setup()

    from django.test.utils import get_runner
    test_runner = get_runner(settings)(verbosity=2)
    failures = test_runner.run_tests(labels or ['django_aws_ses'])
    sys.exit(bool(failures))


if __name__ == '__main__':
    main(sys.argv[1:])
