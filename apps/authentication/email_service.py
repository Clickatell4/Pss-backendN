from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
import logging

logger = logging.getLogger("django.security.auth")


def send_email(subject, to, template_name, context):
    """
    Sends both HTML + TXT version of an email.
    template_name should NOT include extension.
    Example: send_email("Welcome", "x@x.com", "welcome", context)
    """

    html_template = f"emails/html/{template_name}.html"
    txt_template = f"emails/txt/{template_name}.txt"

    try:
        html_body = render_to_string(html_template, context)
        text_body = render_to_string(txt_template, context)

        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[to],
        )

        msg.attach_alternative(html_body, "text/html")
        msg.send()

        logger.info(f"Email sent successfully to {to}")

    except Exception as e:
        logger.error(f"Failed to send email to {to}: {str(e)}")
