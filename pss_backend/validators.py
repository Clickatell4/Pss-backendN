"""
Input validation and sanitization utilities for security.
Minimal version for SCRUM-11 (full version in SCRUM-7).
"""
import html
from django.core.exceptions import ValidationError


def sanitize_text(text, max_length=None, allow_html=False):
    """
    Sanitize text input to prevent XSS attacks.

    Args:
        text (str): The text to sanitize
        max_length (int, optional): Maximum allowed length
        allow_html (bool): Whether to allow HTML tags (default: False)

    Returns:
        str: Sanitized text
    """
    if not text:
        return text

    # Remove null bytes
    text = text.replace('\x00', '')

    # Escape HTML unless explicitly allowed
    if not allow_html:
        text = html.escape(text)

    # Truncate if max_length specified
    if max_length and len(text) > max_length:
        text = text[:max_length]

    return text


def validate_text_length(text, min_length=None, max_length=None, field_name='Field'):
    """
    Validate text length constraints.

    Args:
        text (str): The text to validate
        min_length (int, optional): Minimum allowed length
        max_length (int, optional): Maximum allowed length
        field_name (str): Name of the field for error messages

    Raises:
        ValidationError: If length constraints are violated
    """
    if text is None:
        return

    text_length = len(text)

    if min_length is not None and text_length < min_length:
        raise ValidationError(
            f'{field_name} must be at least {min_length} characters long.'
        )

    if max_length is not None and text_length > max_length:
        raise ValidationError(
            f'{field_name} must not exceed {max_length} characters.'
        )
