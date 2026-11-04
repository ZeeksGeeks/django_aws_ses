# Changelog

All notable changes to `django_aws_ses` will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## \[0.1.7\] - 2026-11-03

### Added

- RFC 8058 one-click unsubscribe endpoint `unsubscribe/one-click/<token>/` (`aws_ses_one_click_unsubscribe`): unsubscribes only on POST with the form body `List-Unsubscribe=One-Click` (otherwise 400); GET/HEAD redirect to the confirmation page without changing state; other methods return 405.
- `django_aws_ses.unsubscribe.list_unsubscribe_headers()` and `list_unsubscribe_headers()` methods on `AwsSesUserAddon` and `EmailUnsubscribe`, returning `List-Unsubscribe` / `List-Unsubscribe-Post` headers.
- `AWS_SES_AUTO_LIST_UNSUBSCRIBE` (default `False`): the backend adds one-click headers to single-recipient messages it can map to a user or `EmailUnsubscribe` record. It also turns on the `EmailUnsubscribe` filter, and `SESBackend` raises `ImproperlyConfigured` when created if `AWS_SES_UNSUBSCRIBE_BASE_URL` is missing.
- `AWS_SES_UNSUBSCRIBE_BASE_URL`: absolute origin used to build one-click URLs (required for one-click; never guessed).
- `AWS_SES_UNSUBSCRIBE_URL`: string containing `{token}` (the token is percent-encoded) or callable, so unsubscribe links can point to an app's own frontend.
- Token-only confirmation page `unsubscribe/token/<token>/` (`aws_ses_unsubscribe_token`) for both user and email-only records.
- JSON API `unsubscribe/api/<token>/` (`aws_ses_unsubscribe_api`) and helpers in `django_aws_ses.unsubscribe` (`resolve_token`, `get_status`, `set_unsubscribed`) for custom frontends. No DRF dependency.
- Transactional opt-out: `message.aws_ses_transactional = True` or the `X-Django-AWS-SES-Transactional` header (stripped before sending) skips only the unsubscribe filter for that message.
- `AWS_SES_FILTER_EMAIL_UNSUBSCRIBES` (default `False`): also drop recipients whose `EmailUnsubscribe` record is unsubscribed.
- `AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS` (default `True`).
- `runtests.py` / `test_urls.py` for running the test suite without a host project; tests cover Django 3.2, 4.2, 5.2 and 6.0.
- `AWS_SES_BOUNCE_TOPIC_ARNS` (default `()`, any topic): SNS topic ARNs the bounce endpoint accepts. Messages and subscription requests from other topics are ignored, even when validly signed. When empty, a warning is logged once per process.
- SNS `SignatureVersion` 2 (SHA256) support on the bounce endpoint. Unknown signature versions are rejected.

### Changed

- Unsubscribe URL generators now return `/unsubscribe/token/<token>/` (or `AWS_SES_UNSUBSCRIBE_URL`) instead of the uuid / encoded-email routes. The old routes still work and accept both token formats.
- The SES backend builds messages with a 998-character line limit. On Django 6 this stops long headers such as `List-Unsubscribe` from being RFC 2047-encoded; on all versions it stops them being folded. ASCII bodies with lines over 78 characters are sent as `7bit` instead of `quoted-printable`.
- When `List-Unsubscribe` headers are present, they are added to the DKIM signed-header list for library-side DKIM signing.
- The unsubscribe filter logs the addresses it drops.
- `HandleUnsubscribe`, `HandleEmailUnsubscribe` and `HandleTokenUnsubscribe` now share a base class, `UnsubscribePageView`; subclasses supply `get_record()`. Unsubscribe page logs identify records by pk instead of email address.
- Removed unused imports from `models.py`, `views.py`, `backends.py`, `utils.py` and `settings.py`.

### Fixed

- Recipient filters (unsubscribe, complaint, bounce, previously-sent, blacklisted domain) compare addresses case-insensitively.
- `SES_BOUNCE_LIMIT` now counts bounces per address. Previously each bounce row was counted separately, so a limit of 1 blocked after one bounce and any higher limit never blocked. Sites with `SES_BOUNCE_LIMIT > 1` will now see addresses blocked once they reach the limit.
- Recipients written as `"Name <user@example.com>"` are matched by their address. Previously they matched no filter, and the domain check read the domain as `example.com>` and silently dropped them.
- The unsubscribe template now includes `{% csrf_token %}`; previously form submissions failed with 403 under `CsrfViewMiddleware`.
- A legacy email-only token used on the user unsubscribe route no longer raises an error.
- Removed the undeclared `pytz` dependency. `views.py` imported it but it was not in `install_requires`, so a fresh install on Django 4.0+ failed with `ModuleNotFoundError: No module named 'pytz'` when the URLs or views were imported. The SES stats dashboard now uses `django.utils.timezone` to convert timestamps to `TIME_ZONE`.
- Library-side DKIM signing (`DKIM_*` settings) now works. The backend passed the message to dkimpy as `str`, signing failed with `cannot use a bytes pattern on a string-like object`, and every message was sent unsigned; this predates 0.1.7. Messages are now signed as bytes, so `List-Unsubscribe` / `List-Unsubscribe-Post` are covered by the signature when present. `RawMessage['Data']` passed to SES is now `bytes`.
- **Security:** SNS signature verification on the bounce endpoint could be bypassed. Any `SigningCertURL` on `*.amazonaws.com` was trusted, including S3 buckets, so anyone could host their own certificate and send validly "signed" fake bounces and complaints. Certificates are now only downloaded over https from `sns.<region>.amazonaws.com` (or `.amazonaws.com.cn`) with a `.pem` path; `AWS_SNS_BOUNCE_CERT_TRUSTED_DOMAINS` can narrow this but no longer widen it. ([#9](https://github.com/ZeeksGeeks/django_aws_ses/issues/9))
- Subscription confirmation only requests a `SubscribeURL` on an SNS host, including when signature verification is turned off.
- An SNS `UnsubscribeConfirmation` no longer re-subscribes the endpoint. The view requested its `SubscribeURL`, which in an unsubscribe message subscribes the endpoint again, so unsubscribing the endpoint from a topic never stuck. It is now only acknowledged.
- SNS signing certificates are cached for 24 hours by URL instead of downloaded for every message. Certificate downloads and subscription confirmations time out after 10 seconds; a failed download rejects the message instead of raising an error.
### Security

- Unsubscribe tokens now carry only the record kind and id, signed with a dedicated salt; the email address no longer appears in unsubscribe links (previously readable in the token, and base64-encoded in the email-only route).
- All unsubscribe confirmation pages show the address masked (`a***@example.com`), so a forwarded link does not reveal it.
- The one-click GET redirect only follows validly signed tokens, and tokens are percent-encoded in `AWS_SES_UNSUBSCRIBE_URL`, so a crafted link cannot add parameters to the frontend URL.
- Tokens issued by 0.1.6 and earlier are still accepted until the next major version, or until `AWS_SES_UNSUBSCRIBE_ACCEPT_LEGACY_TOKENS = False`.

### Known Issues

- On SQLite, case-insensitive address matching covers ASCII letters only.

### Notes

- No migrations.

## \[0.1.6\] - 2026-04-28

### Added

- `EmailUnsubscribe` model for tracking unsubscribe state for bare email addresses not linked to a `User` account — enables mailing-list style sends where recipients may not yet have accounts.
- `HandleEmailUnsubscribe` view — GET/POST handler for email-only unsubscribe flows using a URL-safe base64-encoded email and a `Signer`-signed self-authenticating token (no session or login required).
- URL pattern `unsubscribe/email/<encoded_email>/<token>/` named `aws_ses_email_unsubscribe`.
- Migration `0003_emailunsubscribe` creating the `django_aws_ses_emailunsubscribe` table.

### Notes

- Run `python manage.py migrate django_aws_ses` after upgrading.

## \[0.1.5\] - 2025-12-05

### Added

- Optional IAM role authentication for AWS SES backend.
- IAM role configuration examples in documentation.

### Changed

- Updated SES backend to conditionally use credentials when provided.
- Maintained backward compatibility with access key authentication.

### Removed

- `AwsSesSettings` model and `django.contrib.sites` framework dependency.

### Breaking Changes

- `AwsSesSettings` model removed. Run `python manage.py migrate django_aws_ses` after upgrading.
- `django.contrib.sites` is no longer required.


## \[0.1.4\] - 2025-04-23

### Added

- Note in `README.md` Usage section about sending email attachments with a 10MB size limit.

### Notes

- Prepared for PyPI release, building on TestPyPI validation (`https://test.pypi.org/project/django-aws-ses`).

## \[0.1.3\] - 2025-04-23

### Added

- `Contributing` section in `README.md` with guidelines for contributing to the project.
- Full URLs for `CHANGELOG.md`, `CONTRIBUTORS.md`, and `LICENSE` in `README.md` to ensure PyPI compatibility.

### Changed

- Removed clickable table of contents links in `README.md` for reliable rendering on PyPI.
- Updated `README.md` formatting to streamline structure and improve readability.

### Notes

- Released on TestPyPI (`https://test.pypi.org/project/django-aws-ses`).

## \[0.1.2\] - 2025-04-22

### Added

- `CHANGELOG.md` to document version history.
- Table of contents in `README.md` for improved navigation.
- Expanded `README.md` sections for AWS SES configuration and usage, with detailed instructions and AWS documentation links.
- Note in `README.md` Usage section clarifying examples are in a Python console.

### Changed

- Updated `README.md` to use `https://yourdomain.com` consistently for example URLs.
- Improved `README.md` formatting for better rendering on PyPI and TestPyPI.
- Corrected model references in `README.md` to include `BounceRecord`, `ComplaintRecord`, `SendRecord`, and `AwsSesUserAddon`.

### Notes

- Validated on TestPyPI (`https://test.pypi.org/project/django-aws-ses`).

## \[0.1.1\] - 2025-04-22

### Added

- Comprehensive installation steps in `README.md`, covering PyPI and dependency options (`dev`, `dkim`).
- `CONTRIBUTORS.md` to acknowledge ZeeksGeeks team members and their roles.

### Changed

- Incremented version to `0.1.1` to reflect documentation improvements.

## \[0.1.0\] - 2025-04-15

### Added

- Initial release of `django_aws_ses`.
- Custom Django email backend for Amazon SES.
- Bounce and complaint handling via SNS notifications.
- Non-expiring unsubscribe links with GET vs. POST protection.
- Optional DKIM signing support (requires `dkimpy`).
- Admin dashboard for SES statistics (superusers only).
- Models for `BounceRecord`, `ComplaintRecord`, `SendRecord`, and `AwsSesUserAddon`.
- Comprehensive test suite covering email sending, bounce/complaint handling, and unsubscribe functionality.

### Notes

- Initial release tested with Django 3.2+ and Python 3.6+.
- Successfully deployed to TestPyPI for validation.