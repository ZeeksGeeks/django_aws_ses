# Changelog

All notable changes to `django_aws_ses` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0.2] - 2025-04-22
### Added
- Added CHANGELOG.md 

## [0.1.0.1] - 2025-04-22
### Added
- Comprehensive installation steps in `README.md`, covering PyPI, and dependency options (`dev`, `dkim`).
- `CONTRIBUTORS.md` to acknowledge ZeeksGeeks team members and their roles.
- Changelog (`CHANGELOG.md`) to document version history.

### Changed
- Updated `README.md` formatting for better rendering on TestPyPI/PyPI.
- Incremented version to `0.1.1` to reflect documentation improvements.

## [0.1.0] - 2025-04-15
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
[0.1.0.2]: https://git-vault.zeeksgeeks.com/ZeeksGeeks/django_aws_ses/compare/0.1.0.1...0.1.0.2
[0.1.0.1]: https://git-vault.zeeksgeeks.com/ZeeksGeeks/django_aws_ses/compare/0.1.0...0.1.0.1
[0.1.0]: https://git-vault.zeeksgeeks.com/ZeeksGeeks/django_aws_ses/releases/tag/0.1.0