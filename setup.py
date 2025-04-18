from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="django_aws_ses",
    version="0.1.0",
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "django>=3.2",
        "boto3>=1.18",
        "requests>=2.25",
        "cryptography>=3.4",
        "dnspython>=2.1",
        "pytz>=2021.1",
    ],
    extras_require={
        "dkim": ["dkimpy>=1.0"],
    },
    author="Ray Jessop",
    author_email="development@zeeksgeeks.com",
    description="A Django email backend for Amazon SES",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zeeksgeeks/django_aws_ses",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.0",
        "Framework :: Django :: 4.2",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Communications :: Email",
    ],
)