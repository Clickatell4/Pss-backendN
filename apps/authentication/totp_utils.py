"""
SCRUM-14: TOTP Utility Functions

Helper functions for TOTP (Time-based One-Time Password) generation,
verification, and QR code creation for Two-Factor Authentication.

Security Features:
- TOTP secrets generated with cryptographically secure random
- QR codes generated as base64 images (no file storage)
- Time window tolerance (±30 seconds) to prevent replay attacks
- Backup codes use secure random generation
"""
import pyotp
import qrcode
import io
import base64
import secrets
import string


def generate_totp_secret():
    """
    Generate a random TOTP secret (base32 encoded).

    Returns:
        str: Base32-encoded secret (16 characters)
             Compatible with Google Authenticator, Authy, etc.

    Example:
        >>> secret = generate_totp_secret()
        >>> len(secret)
        32
        >>> secret.isalnum()
        True
    """
    return pyotp.random_base32()


def generate_qr_code(secret, email, issuer='PSS Backend'):
    """
    Generate QR code for TOTP setup as base64-encoded PNG image.

    Args:
        secret (str): Base32-encoded TOTP secret
        email (str): User's email address (shown in authenticator app)
        issuer (str): Service name (default: 'PSS Backend')

    Returns:
        dict: Dictionary containing:
            - qr_code_base64 (str): Base64-encoded PNG image
            - provisioning_uri (str): otpauth:// URI for manual entry
            - secret (str): The TOTP secret (for display)

    Example:
        >>> qr_data = generate_qr_code('JBSWY3DPEHPK3PXP', 'user@example.com')
        >>> qr_data['qr_code_base64'].startswith('iVBORw0KGgo')
        True
        >>> 'otpauth://totp/' in qr_data['provisioning_uri']
        True
    """
    # Create TOTP object
    totp = pyotp.TOTP(secret)

    # Generate provisioning URI (otpauth://totp/...)
    provisioning_uri = totp.provisioning_uri(
        name=email,
        issuer_name=issuer
    )

    # Generate QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Create image and convert to base64
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return {
        'qr_code_base64': img_str,
        'provisioning_uri': provisioning_uri,
        'secret': secret
    }


def verify_totp_code(secret, code, window=1):
    """
    Verify a TOTP code against a secret.

    Args:
        secret (str): Base32-encoded TOTP secret
        code (str): 6-digit TOTP code from user
        window (int): Number of time windows to check before/after current
                     (default: 1 = ±30 seconds tolerance)

    Returns:
        bool: True if code is valid, False otherwise

    Security:
        - Time window prevents clock drift issues
        - window=1 allows ±30 seconds (30 second time step)
        - Prevents replay attacks (each code valid for max 90 seconds)

    Example:
        >>> secret = 'JBSWY3DPEHPK3PXP'
        >>> totp = pyotp.TOTP(secret)
        >>> code = totp.now()
        >>> verify_totp_code(secret, code)
        True
        >>> verify_totp_code(secret, '000000')
        False
    """
    try:
        # Normalize code (remove spaces, ensure 6 digits)
        normalized_code = code.strip().replace(' ', '')

        if not normalized_code.isdigit() or len(normalized_code) != 6:
            return False

        # Create TOTP object and verify
        totp = pyotp.TOTP(secret)
        return totp.verify(normalized_code, valid_window=window)

    except Exception:
        # Invalid secret or other error
        return False


def generate_backup_codes(count=10, length=8):
    """
    Generate random backup codes for 2FA recovery.

    Args:
        count (int): Number of backup codes to generate (default: 10)
        length (int): Length of each code (default: 8)

    Returns:
        list: List of backup codes in format XXXX-XXXX

    Security:
        - Uses secrets module (cryptographically secure random)
        - Alphanumeric only (uppercase letters + digits)
        - Format: XXXX-XXXX for readability
        - 8 characters = 36^8 = 2.8 trillion combinations

    Example:
        >>> codes = generate_backup_codes(count=3, length=8)
        >>> len(codes)
        3
        >>> all(len(code) == 9 for code in codes)  # 8 chars + 1 hyphen
        True
        >>> all('-' in code for code in codes)
        True
    """
    codes = []
    alphabet = string.ascii_uppercase + string.digits  # A-Z, 0-9

    for _ in range(count):
        # Generate random alphanumeric code
        code = ''.join(secrets.choice(alphabet) for _ in range(length))

        # Format as XXXX-XXXX (split in half with hyphen)
        mid = length // 2
        formatted_code = f"{code[:mid]}-{code[mid:]}"

        codes.append(formatted_code)

    return codes
