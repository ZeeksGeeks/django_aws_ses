from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .views import (
    dashboard,
    handle_bounce,
    HandleUnsubscribe,
    HandleEmailUnsubscribe,
    HandleTokenUnsubscribe,
    one_click_unsubscribe,
    unsubscribe_api,
)

app_name = "django_aws_ses"

urlpatterns = [
    path('status/', dashboard, name='aws_ses_status'),
    path('bounce/', csrf_exempt(handle_bounce), name='aws_ses_bounce'),
    # Token-only routes must come before 'unsubscribe/<uuid>/<token>/', which would otherwise match them.
    path('unsubscribe/token/<str:token>/', HandleTokenUnsubscribe.as_view(), name='aws_ses_unsubscribe_token'),
    path('unsubscribe/one-click/<str:token>/', one_click_unsubscribe, name='aws_ses_one_click_unsubscribe'),
    path('unsubscribe/api/<str:token>/', unsubscribe_api, name='aws_ses_unsubscribe_api'),
    path('unsubscribe/<str:uuid>/<str:token>/', HandleUnsubscribe.as_view(), name='aws_ses_unsubscribe'),
    path('unsubscribe/email/<str:encoded_email>/<str:token>/', HandleEmailUnsubscribe.as_view(), name='aws_ses_email_unsubscribe'),
]
