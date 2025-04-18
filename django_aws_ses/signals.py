from django.dispatch import Signal

# Exported signals
__all__ = (
    'bounce_received',
    'complaint_received',
    'delivery_received',
    'email_pre_send',
    'email_post_send',
)

bounce_received = Signal()
"""Signal sent when an AWS SES bounce notification is received.

Args:
    sender: The view or function handling the bounce (e.g., handle_bounce).
    mail_obj (dict): SES mail object containing email details.
    bounce_obj (dict): SES bounce details (e.g., bounceType, feedbackId).
    raw_message (bytes): Raw SNS notification payload.
"""

complaint_received = Signal()
"""Signal sent when an AWS SES complaint notification is received.

Args:
    sender: The view or function handling the complaint (e.g., handle_bounce).
    mail_obj (dict): SES mail object containing email details.
    complaint_obj (dict): SES complaint details (e.g., feedbackType, feedbackId).
    raw_message (bytes): Raw SNS notification payload.
"""

delivery_received = Signal()
"""Signal sent when an AWS SES delivery or send notification is received.

Args:
    sender: The view or function handling the delivery (e.g., handle_bounce).
    mail_obj (dict): SES mail object containing email details.
    delivery_obj (dict): SES delivery details (e.g., messageId, destination).
    raw_message (bytes): Raw SNS notification payload.
"""

email_pre_send = Signal()
"""Signal sent before an email is sent via SES.

Args:
    sender: The SESBackend class.
    message (EmailMessage): The Django EmailMessage object to be sent.
"""

email_post_send = Signal()
"""Signal sent after an email is sent via SES.

Args:
    sender: The SESBackend class.
    message (EmailMessage): The Django EmailMessage object sent.

Note:
    This signal is reserved for future functionality to handle post-send processing.
"""