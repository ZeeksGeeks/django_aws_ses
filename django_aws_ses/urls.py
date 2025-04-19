from django.urls import include, path
from django.views.decorators.csrf import csrf_exempt

from .views import (
    dashboard, 
    handle_bounce,
    HandleUnsubscribe
    )

app_name = "django_aws_ses"

urlpatterns = [
    path('status/', dashboard, name='aws_ses_status'),
    path('bounce/', csrf_exempt(handle_bounce),name='aws_ses_bounce'),
    path('unsubscribe/<str:uuid>/<str:token>/', HandleUnsubscribe.as_view(), name='aws_ses_unsubscribe')
]