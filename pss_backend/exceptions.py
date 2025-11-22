"""
Custom exception handling for the PSS Backend.

This module provides secure exception handling that:
- Returns generic error messages to clients
- Logs detailed error information server-side
- Prevents information disclosure (OWASP A05:2021)
"""

import logging
import traceback
import uuid

from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework.exceptions import (
    APIException,
    ValidationError,
    AuthenticationFailed,
    NotAuthenticated,
    PermissionDenied,
    NotFound,
)

logger = logging.getLogger('django.security')


def custom_exception_handler(exc, context):
    """
    Custom exception handler that sanitizes error responses.

    - Known/expected exceptions: Return appropriate error messages
    - Unexpected exceptions: Return generic message, log details server-side

    Args:
        exc: The exception instance
        context: Dict with 'view', 'args', 'kwargs', 'request'

    Returns:
        Response object with sanitized error data
    """
    # Generate a unique error ID for tracking
    error_id = str(uuid.uuid4())[:8]

    # Get the standard DRF response first
    response = exception_handler(exc, context)

    # Get request info for logging
    request = context.get('request')
    view = context.get('view')
    view_name = view.__class__.__name__ if view else 'Unknown'

    # If DRF handled it, it's a known exception type
    if response is not None:
        # Sanitize the response data
        response.data = _sanitize_response_data(response.data, exc)
        response.data['error_id'] = error_id

        # Log the error with details (server-side only)
        _log_exception(exc, error_id, request, view_name, response.status_code)

        return response

    # Handle Django's ValidationError
    if isinstance(exc, DjangoValidationError):
        _log_exception(exc, error_id, request, view_name, 400)
        return Response(
            {
                'detail': 'Validation error',
                'error_id': error_id
            },
            status=status.HTTP_400_BAD_REQUEST
        )

    # Handle Http404
    if isinstance(exc, Http404):
        _log_exception(exc, error_id, request, view_name, 404)
        return Response(
            {
                'detail': 'Not found',
                'error_id': error_id
            },
            status=status.HTTP_404_NOT_FOUND
        )

    # Unhandled exception - log full details, return generic message
    _log_exception(exc, error_id, request, view_name, 500, include_traceback=True)

    return Response(
        {
            'detail': 'An unexpected error occurred. Please try again later.',
            'error_id': error_id
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


def _sanitize_response_data(data, exc):
    """
    Sanitize response data to remove potentially sensitive information.

    Args:
        data: The original response data dict
        exc: The exception instance

    Returns:
        Sanitized response data dict
    """
    if isinstance(data, dict):
        sanitized = {}

        # Keep 'detail' if it's a string (DRF's standard field)
        if 'detail' in data:
            detail = data['detail']
            # Check if detail is a safe, expected message
            if isinstance(detail, str) and not _contains_sensitive_info(detail):
                sanitized['detail'] = detail
            else:
                # Use a generic message based on exception type
                sanitized['detail'] = _get_safe_message(exc)

        # Keep validation errors (field-level) but sanitize values
        if isinstance(exc, ValidationError):
            if 'errors' in data or any(k not in ('detail', 'error_id') for k in data.keys()):
                sanitized['errors'] = _sanitize_validation_errors(data)

        return sanitized

    return {'detail': _get_safe_message(exc)}


def _sanitize_validation_errors(data):
    """
    Sanitize validation errors to keep field names but sanitize messages.

    Args:
        data: The original error data

    Returns:
        Sanitized validation errors dict
    """
    errors = {}

    for key, value in data.items():
        if key in ('detail', 'error_id'):
            continue

        if isinstance(value, list):
            # Keep simple validation messages, sanitize complex ones
            errors[key] = [
                msg if isinstance(msg, str) and not _contains_sensitive_info(msg)
                else 'Invalid value'
                for msg in value
            ]
        elif isinstance(value, str):
            if not _contains_sensitive_info(value):
                errors[key] = [value]
            else:
                errors[key] = ['Invalid value']

    return errors if errors else None


def _contains_sensitive_info(message):
    """
    Check if a message potentially contains sensitive information.

    Args:
        message: The message string to check

    Returns:
        True if message may contain sensitive info, False otherwise
    """
    if not isinstance(message, str):
        return True

    sensitive_patterns = [
        # File paths
        '/', '\\', '.py', '.sql',
        # Database info
        'psycopg', 'django.db', 'SELECT', 'INSERT', 'UPDATE', 'DELETE',
        'column', 'table', 'relation', 'constraint',
        # Stack traces
        'Traceback', 'File "', 'line ', 'raise ',
        # Internal details
        'NoneType', 'AttributeError', 'KeyError', 'TypeError',
        'IndexError', 'ValueError', 'IntegrityError',
        # Secrets
        'key', 'token', 'secret', 'password', 'credential',
    ]

    message_lower = message.lower()
    return any(pattern.lower() in message_lower for pattern in sensitive_patterns)


def _get_safe_message(exc):
    """
    Get a safe, generic error message based on exception type.

    Args:
        exc: The exception instance

    Returns:
        Safe error message string
    """
    if isinstance(exc, AuthenticationFailed):
        return 'Authentication failed'
    elif isinstance(exc, NotAuthenticated):
        return 'Authentication required'
    elif isinstance(exc, PermissionDenied):
        return 'Permission denied'
    elif isinstance(exc, NotFound):
        return 'Resource not found'
    elif isinstance(exc, ValidationError):
        return 'Validation error'
    elif isinstance(exc, APIException):
        # Use the default detail if it's safe
        default_detail = getattr(exc, 'default_detail', None)
        if default_detail and not _contains_sensitive_info(str(default_detail)):
            return str(default_detail)
        return 'Request could not be processed'
    else:
        return 'An unexpected error occurred'


def _log_exception(exc, error_id, request, view_name, status_code, include_traceback=False):
    """
    Log exception details server-side for debugging.

    Args:
        exc: The exception instance
        error_id: Unique identifier for this error
        request: The HTTP request
        view_name: Name of the view that raised the exception
        status_code: HTTP status code being returned
        include_traceback: Whether to include full traceback
    """
    # Build log context
    user_id = getattr(request.user, 'id', 'anonymous') if request else 'unknown'
    method = request.method if request else 'unknown'
    path = request.path if request else 'unknown'

    log_data = {
        'error_id': error_id,
        'exception_type': exc.__class__.__name__,
        'exception_message': str(exc),
        'view': view_name,
        'method': method,
        'path': path,
        'user_id': user_id,
        'status_code': status_code,
    }

    if include_traceback:
        log_data['traceback'] = traceback.format_exc()

    # Log at appropriate level
    if status_code >= 500:
        logger.error(f"Server error [{error_id}]: {log_data}")
    elif status_code >= 400:
        logger.warning(f"Client error [{error_id}]: {log_data}")
    else:
        logger.info(f"Exception handled [{error_id}]: {log_data}")
