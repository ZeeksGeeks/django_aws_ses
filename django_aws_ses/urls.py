from django.conf.urls import include, url
from django.views.decorators.csrf import csrf_exempt

from .views import (
    dashboard, 
    handle_bounce,
    HandleUnsubscribe
    )

app_name = "django_aws_ses"

urlpatterns = [
    url(r'^status/$', dashboard, name='aws_ses_status'),
    url(r'^bounce/$', csrf_exempt(handle_bounce),name='aws_ses_bounce'),
    url(r'^unsubscribe/(?P<uuid>[0-9a-zA-Z]+)/(?P<hash>[0-9a-zA-Z]+)/$', HandleUnsubscribe.as_view(), name='aws_ses_unsubscribe')
]
