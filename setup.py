from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="django_aws_ses",
    version="0.1.1",
    author="ZeeksGeeks",
    author_email="contact@zeeksgeeks.com",
    description="A Django email backend for Amazon SES with bounce and complaint handling",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://git-vault.zeeksgeeks.com/public/django_aws_ses",  # Replace with your repo or website
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'django>=3.2',
        'boto3>=1.18.0',
        'requests>=2.26.0',
        'cryptography>=3.4.7',
        'dnspython>=2.1.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-django>=4.5.0',
            'mock>=4.0.3',
        ],
        'dkim': [
            'dkimpy>=1.0.0',  # Optional for DKIM signing
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: Django",
    ],
    python_requires='>=3.6',
)