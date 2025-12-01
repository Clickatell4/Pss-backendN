"""
SCRUM-7: Input validation and sanitization utilities
Prevents injection attacks (SQL, XSS, Command injection, Path traversal)
OWASP A03:2021 - Injection
"""
import re
import html
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator


# =============================================================================
# Text Sanitization
# =============================================================================

def sanitize_text(text, max_length=None, allow_html=False):
    """
    Sanitize text input to prevent XSS attacks.

    Args:
        text: Input string to sanitize
        max_length: Maximum allowed length (None for no limit)
        allow_html: If False, escapes all HTML (default behavior)

    Returns:
        Sanitized text string

    Raises:
        ValidationError: If text exceeds max_length
    """
    if text is None:
        return None

    if not isinstance(text, str):
        text = str(text)

    # Strip leading/trailing whitespace
    text = text.strip()

    # Check length
    if max_length and len(text) > max_length:
        raise ValidationError(
            f'Text exceeds maximum length of {max_length} characters (got {len(text)})'
        )

    # Escape HTML to prevent XSS
    if not allow_html:
        text = html.escape(text)

    return text


def sanitize_html(text, max_length=None):
    """
    Sanitize HTML content - allows basic formatting but removes dangerous tags.

    Args:
        text: HTML string to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized HTML string
    """
    if text is None:
        return None

    if not isinstance(text, str):
        text = str(text)

    # Remove script tags and their content
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)

    # Remove event handlers (onclick, onerror, etc.)
    text = re.sub(r'\s*on\w+\s*=\s*["\']?[^"\'>]*["\']?', '', text, flags=re.IGNORECASE)

    # Remove javascript: protocol
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)

    # Remove data: protocol (can be used for XSS)
    text = re.sub(r'data:', '', text, flags=re.IGNORECASE)

    # Check length after sanitization
    if max_length and len(text) > max_length:
        raise ValidationError(
            f'HTML content exceeds maximum length of {max_length} characters'
        )

    return text.strip()


# =============================================================================
# Field Validators
# =============================================================================

def validate_phone_number(phone):
    """
    Validate phone number format (SA format).
    Accepts: +27XXXXXXXXX, 0XXXXXXXXX, or XXXXXXXXXX
    """
    if not phone:
        return phone

    # Remove spaces and dashes
    phone = re.sub(r'[\s\-]', '', phone)

    # Check format
    if not re.match(r'^(\+27|0)?[0-9]{9,10}$', phone):
        raise ValidationError(
            'Invalid phone number format. Use format: +27XXXXXXXXX or 0XXXXXXXXX'
        )

    return phone


def validate_id_number(id_number):
    """
    Validate South African ID number format.
    Format: YYMMDDGSSSCAZ (13 digits)
    """
    if not id_number:
        return id_number

    # Remove spaces
    id_number = id_number.replace(' ', '')

    # Must be 13 digits
    if not re.match(r'^\d{13}$', id_number):
        raise ValidationError(
            'Invalid South African ID number. Must be 13 digits.'
        )

    # Validate date portion (YYMMDD)
    year = int(id_number[0:2])
    month = int(id_number[2:4])
    day = int(id_number[4:6])

    if month < 1 or month > 12:
        raise ValidationError('Invalid ID number: month must be between 01 and 12')

    if day < 1 or day > 31:
        raise ValidationError('Invalid ID number: day must be between 01 and 31')

    return id_number


def validate_email_domain(email, allowed_domains=None):
    """
    Validate email domain against whitelist.

    Args:
        email: Email address to validate
        allowed_domains: List of allowed domains (default: ['capaciti.org.za'])
    """
    if not email:
        return email

    if allowed_domains is None:
        allowed_domains = ['capaciti.org.za']

    email = email.lower().strip()

    if '@' not in email:
        raise ValidationError('Invalid email format')

    domain = email.split('@')[1]

    if domain not in allowed_domains:
        raise ValidationError(
            f'Email domain must be one of: {", ".join(allowed_domains)}'
        )

    return email


def validate_enum_choice(value, allowed_choices, field_name='field'):
    """
    Whitelist-based validation for enum/choice fields.

    Args:
        value: Value to validate
        allowed_choices: List of allowed values or list of (value, label) tuples
        field_name: Name of field for error message

    Raises:
        ValidationError: If value not in allowed choices
    """
    if value is None:
        return None

    # Extract values if choices are tuples
    if allowed_choices and isinstance(allowed_choices[0], (list, tuple)):
        allowed_values = [choice[0] for choice in allowed_choices]
    else:
        allowed_values = allowed_choices

    if value not in allowed_values:
        raise ValidationError(
            f'Invalid {field_name}: "{value}". Must be one of: {", ".join(str(v) for v in allowed_values)}'
        )

    return value


def validate_text_length(text, min_length=None, max_length=None, field_name='field'):
    """
    Validate text length constraints.

    Args:
        text: Text to validate
        min_length: Minimum length (None for no minimum)
        max_length: Maximum length (None for no maximum)
        field_name: Name of field for error message
    """
    if text is None:
        return None

    text_length = len(text)

    if min_length and text_length < min_length:
        raise ValidationError(
            f'{field_name} must be at least {min_length} characters (got {text_length})'
        )

    if max_length and text_length > max_length:
        raise ValidationError(
            f'{field_name} exceeds maximum length of {max_length} characters (got {text_length})'
        )

    return text


def validate_positive_integer(value, max_value=None, field_name='value'):
    """
    Validate that value is a positive integer within range.

    Args:
        value: Value to validate
        max_value: Maximum allowed value (None for no maximum)
        field_name: Name of field for error message
    """
    if value is None:
        return None

    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f'{field_name} must be a valid integer')

    if value < 0:
        raise ValidationError(f'{field_name} must be a positive integer')

    if max_value and value > max_value:
        raise ValidationError(
            f'{field_name} must be {max_value} or less (got {value})'
        )

    return value


# =============================================================================
# Path Traversal Prevention
# =============================================================================

def validate_safe_path(path, allowed_base_paths=None):
    """
    Prevent path traversal attacks.

    Args:
        path: File path to validate
        allowed_base_paths: List of allowed base directories

    Raises:
        ValidationError: If path contains traversal attempts or is outside allowed paths
    """
    if not path:
        return path

    # Normalize path
    import os
    path = os.path.normpath(path)

    # Check for path traversal patterns
    if '..' in path or path.startswith('/'):
        raise ValidationError('Invalid path: path traversal detected')

    # If allowed base paths specified, ensure path is within them
    if allowed_base_paths:
        is_safe = False
        for base_path in allowed_base_paths:
            full_path = os.path.join(base_path, path)
            if os.path.commonpath([base_path, full_path]) == base_path:
                is_safe = True
                break

        if not is_safe:
            raise ValidationError('Invalid path: outside allowed directories')

    return path


# =============================================================================
# SQL Injection Prevention (for raw queries)
# =============================================================================

def validate_sql_identifier(identifier):
    """
    Validate SQL identifiers (table names, column names) to prevent SQL injection.
    Only allows alphanumeric characters and underscores.

    Note: This should only be used when you absolutely must use raw SQL.
    Prefer Django ORM which prevents SQL injection automatically.
    """
    if not identifier:
        return identifier

    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
        raise ValidationError(
            'Invalid SQL identifier: only letters, numbers, and underscores allowed'
        )

    # Prevent SQL keywords as identifiers
    sql_keywords = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'EXEC', 'EXECUTE', 'UNION', 'WHERE', 'FROM', 'TABLE', 'DATABASE'
    }

    if identifier.upper() in sql_keywords:
        raise ValidationError(f'Invalid identifier: "{identifier}" is a reserved SQL keyword')

    return identifier


# =============================================================================
# Django Validators (for model fields)
# =============================================================================

# Alphanumeric + spaces only (for names)
alphanumeric_spaces_validator = RegexValidator(
    regex=r'^[a-zA-Z0-9\s]+$',
    message='Only letters, numbers, and spaces are allowed'
)

# Alphanumeric + basic punctuation (for text fields)
safe_text_validator = RegexValidator(
    regex=r'^[a-zA-Z0-9\s.,;:!?\-\'\"()]+$',
    message='Contains invalid characters'
)
