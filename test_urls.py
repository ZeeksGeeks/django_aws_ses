"""Root URLconf used by runtests.py."""
from django.urls import include, path

urlpatterns = [
    path('aws_ses/', include('django_aws_ses.urls', namespace='django_aws_ses')),
]
