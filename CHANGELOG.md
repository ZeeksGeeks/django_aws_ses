# Changelog

All notable changes to `django_aws_ses` will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## 0.1.3 - 2025-04-23

### Added

- `Contributing` section in `README.md` with guidelines for contributing to the project.
- Full URLs for `CHANGELOG.md`, `CONTRIBUTORS.md`, and `LICENSE` in `README.md` to ensure PyPI compatibility.

### Changed

- Removed clickable table of contents links in `README.md` for reliable rendering on PyPI.
- Updated `README.md` formatting to streamline structure and improve readability.

### Notes

- Prepared for PyPI release, validated on TestPyPI (`https://test.pypi.org/project/django-aws-ses`).

## 0.1.2 - 2025-04-22

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