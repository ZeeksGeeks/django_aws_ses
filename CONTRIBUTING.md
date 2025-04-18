# Contributing to Django AWS SES

Thank you for your interest in contributing to Django AWS SES! This guide outlines how to set up the project, run tests, and submit changes.

## Getting Started

1. **Clone the Repository**:

   ```bash
   git clone https://git-vault.zeeksgeeks.com/zeeksgeeks/django_aws_ses
   cd django_aws_ses
   ```

2. **Set Up a Virtual Environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Configure a Test Django Project**:

   - Create a Django project or use an existing one.

   - Add `'django_aws_ses'` to `INSTALLED_APPS` in `settings.py`.

   - Apply migrations:

     ```bash
     python manage.py migrate
     ```

## Running Tests

1. Ensure test dependencies are installed:

   ```bash
   pip install -r requirements-dev.txt
   ```

2. Run the test suite:

   ```bash
   python manage.py test django_aws_ses
   ```

3. Check test coverage (optional):

   ```bash
   pytest --cov=django_aws_ses
   ```

## Making Changes

1. **Create a Feature Branch**:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Follow Coding Guidelines**:

   - Write clear, concise code with docstrings.
   - Ensure compatibility with Python 3.8+ and Django 3.2+.
   - Add tests for new functionality.

3. **Test Your Changes**:

   - Run the full test suite to ensure no regressions.
   - Test manually in a Django project if needed.

4. **Commit Changes**:

   ```bash
   git add .
   git commit -m "Add your descriptive commit message"
   ```

5. **Push and Create a Pull Request**:

   ```bash
   git push origin feature/your-feature-name
   ```

   - Create a pull request on the repository.
   - Describe your changes and reference any related issues.

## Reporting Issues

- Use the repository’s issue tracker to report bugs or suggest features.
- Provide detailed information, including steps to reproduce and environment details.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Contact

For questions, contact Ray Jessop at development@zeeksgeeks.com.