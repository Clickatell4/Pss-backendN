"""
SCRUM-7: Request validation middleware
Additional layer of security for all API requests
OWASP A03:2021 - Injection
"""
import json
from django.http import JsonResponse
from django.core.exceptions import SuspiciousOperation


class RequestValidationMiddleware:
    """
    Middleware to validate incoming requests and prevent common attacks.

    Protections:
    - Enforces maximum request body size
    - Validates Content-Type headers
    - Prevents suspiciously large header values
    - Logs suspicious requests
    """

    # Maximum request body size: 10MB (adjust based on your needs)
    MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB

    # Maximum header value size: 8KB (standard HTTP header limit)
    MAX_HEADER_SIZE = 8 * 1024  # 8KB

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Validate request before processing
        try:
            self._validate_request_size(request)
            self._validate_headers(request)
            self._validate_content_type(request)
        except SuspiciousOperation as e:
            return JsonResponse({
                'detail': 'Invalid request',
                'error': str(e)
            }, status=400)

        response = self.get_response(request)
        return response

    def _validate_request_size(self, request):
        """
        Validate that request body size is within acceptable limits.
        Prevents DoS attacks via huge request bodies.
        """
        content_length = request.META.get('CONTENT_LENGTH')

        if content_length:
            try:
                content_length = int(content_length)
                if content_length > self.MAX_BODY_SIZE:
                    raise SuspiciousOperation(
                        f'Request body too large: {content_length} bytes (max: {self.MAX_BODY_SIZE})'
                    )
            except ValueError:
                raise SuspiciousOperation('Invalid Content-Length header')

    def _validate_headers(self, request):
        """
        Validate HTTP headers to prevent header injection attacks.
        """
        for header_name, header_value in request.META.items():
            if not isinstance(header_value, str):
                continue

            # Check header size
            if len(header_value) > self.MAX_HEADER_SIZE:
                raise SuspiciousOperation(
                    f'Header value too large: {header_name}'
                )

            # Check for null bytes (indicates potential injection)
            if '\x00' in header_value:
                raise SuspiciousOperation(
                    f'Null byte detected in header: {header_name}'
                )

            # Check for CRLF injection attempts
            if '\r' in header_value or '\n' in header_value:
                raise SuspiciousOperation(
                    f'CRLF characters detected in header: {header_name}'
                )

    def _validate_content_type(self, request):
        """
        Validate Content-Type header for POST/PUT/PATCH requests.
        Ensures clients send appropriate content types.
        """
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.META.get('CONTENT_TYPE', '')

            # Allow these content types
            allowed_content_types = [
                'application/json',
                'application/x-www-form-urlencoded',
                'multipart/form-data',
            ]

            # Extract base content type (ignore charset, boundary, etc.)
            base_content_type = content_type.split(';')[0].strip().lower()

            # Check if content type is allowed
            if base_content_type and not any(
                base_content_type.startswith(allowed)
                for allowed in allowed_content_types
            ):
                # Log suspicious content type but don't block
                # (some legitimate requests might use other types)
                import logging
                logger = logging.getLogger('django.security')
                logger.warning(
                    f'Unusual Content-Type: {content_type} for {request.method} {request.path}'
                )


class JSONValidationMiddleware:
    """
    Middleware to validate JSON request bodies.
    Prevents malformed JSON from reaching views.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only validate JSON requests
        content_type = request.META.get('CONTENT_TYPE', '')
        if 'application/json' in content_type.lower() and request.body:
            try:
                # Attempt to parse JSON
                json.loads(request.body)
            except json.JSONDecodeError as e:
                return JsonResponse({
                    'detail': 'Invalid JSON in request body',
                    'error': str(e)
                }, status=400)
            except UnicodeDecodeError:
                return JsonResponse({
                    'detail': 'Invalid encoding in request body',
                    'error': 'Request body must be UTF-8 encoded'
                }, status=400)

        response = self.get_response(request)
        return response
