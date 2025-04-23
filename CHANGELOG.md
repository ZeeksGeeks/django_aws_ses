# Changelog

All notable changes to `django_aws_ses` will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## 0.1.2 - 2025-04-22

### Added

- `CHANGELOG.md` to document version history.
- Clickable table of contents in `README.md` for improved navigation.
- Expanded `README.md` sections for AWS SES configuration and usage, with detailed instructions and AWS documentation links.
- Note in `README.md` Usage section clarifying examples are in a Python console.

### Changed

- Updated `README.md` to use `https://yourdomain.com` consistently for example URLs.
- Improved `README.md` formatting for better rendering on PyPI.

## 0.1.1 - 2025-04-22

### Added

- Comprehensive installation steps in `README.md`, covering PyPI and dependency options (`dev`, `dkim`).
- `CONTRIBUTORS.md` to acknowledge ZeeksGeeks team members and their roles.

### Changed

- Incremented version to `0.1.1` to reflect documentation improvements.

## 0.1.0 - 2025-04-15

### Added

- Initial release of `django_aws_ses`.
- Custom Django email backend for Amazon SES.
- Bounce and complaint handling via SNS notifications.
- Non-expiring unsubscribe links with GET vs. POST protection.
- Optional DKIM signing support (requires `dkimpy`).
- Admin dashboard for SES statistics (superusers only).
- Models for `AwsSesSettings`, `BounceRecord`, `ComplaintRecord`, `SendRecord`, and `AwsSesUserAddon`.
- Comprehensive test suite covering email sending, bounce/complaint handling, and unsubscribe functionality.

### Notes

- Initial release tested with Django 3.2+ and Python 3.6+.
- Successfully deployed to TestPyPI for validation.