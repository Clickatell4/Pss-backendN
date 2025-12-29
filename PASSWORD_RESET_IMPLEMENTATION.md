# Password Reset & Change Implementation (SCRUM-117)

## Overview

This document describes the complete password reset and change implementation for the PSS System. All features comply with security best practices and OWASP recommendations.

## API Endpoints

### 1. Password Reset Request
**Endpoint:** `POST /auth/password-reset/request/`

Request user to initiate password reset process.

**Request Body:**
```json
{
    "email": "user@capaciti.org.za"
}
```

**Response (Success - 200):**
```json
{
    "message": "If an account with that email exists, a password reset link has been sent.",
    "detail": "Please check your email for instructions."
}
```

**Response (Rate Limited - 429):**
```json
{
    "detail": "Request was throttled. Expected available in 3600 seconds."
}
```

**Security Features:**
- Rate limited: 3 requests per hour per IP
- Doesn't reveal if email exists in system (prevents email enumeration)
- Returns same message for existing and non-existing emails
- Tracks IP address and user agent for audit trail
- Logs all reset requests

---

### 2. Validate Password Reset Token
**Endpoint:** `POST /auth/password-reset/validate-token/`

Validate token before showing password reset form (frontend coordination).

**Request Body:**
```json
{
    "token": "reset_token_string"
}
```

**Response (Valid Token - 200):**
```json
{
    "valid": true,
    "email": "user@capaciti.org.za",
    "detail": "Token is valid"
}
```

**Response (Invalid/Expired Token - 400):**
```json
{
    "valid": false,
    "detail": "Token is invalid, expired, or already used"
}
```

**Security Features:**
- Allows frontend to validate token without consuming it
- Token hashed in database (not stored plaintext)
- Tokens expire after 1 hour
- Single-use tokens (marked as used after reset)

---

### 3. Confirm Password Reset
**Endpoint:** `POST /auth/password-reset/confirm/`

Confirm password reset with new password.

**Request Body:**
```json
{
    "token": "reset_token_string",
    "new_password": "new_secure_password_123"
}
```

**Response (Success - 200):**
```json
{
    "message": "Password has been reset successfully",
    "detail": "You can now log in with your new password"
}
```

**Response (Invalid Token - 400):**
```json
{
    "detail": "Invalid, expired, or already used token"
}
```

**Response (Weak Password - 400):**
```json
{
    "detail": "Password does not meet requirements",
    "errors": {
        "new_password": [
            "This password is too common.",
            "Your password must contain at least 8 characters."
        ]
    }
}
```

**Security Features:**
- Rate limited: 5 attempts per 15 minutes per IP
- Validates against Django password validators
- Prevents password same as old password
- Invalidates all other sessions after reset
- Sends confirmation email
- Logs password reset events

---

### 4. Password Change (Authenticated Users)
**Endpoint:** `POST /auth/password-change/`

Change password for authenticated user.

**Authentication:** Required (Bearer token)

**Request Body:**
```json
{
    "old_password": "current_password",
    "new_password": "new_secure_password_123"
}
```

**Response (Success - 200):**
```json
{
    "message": "Password changed successfully",
    "detail": "Your password has been updated. You may need to log in again on other devices."
}
```

**Response (Wrong Old Password - 400):**
```json
{
    "detail": "Old password is incorrect",
    "errors": {
        "old_password": ["Password is incorrect"]
    }
}
```

**Response (Password Reuse - 400):**
```json
{
    "detail": "New password cannot be the same as your old password",
    "errors": {
        "new_password": ["Please choose a different password."]
    }
}
```

**Security Features:**
- Requires authentication (protected endpoint)
- Rate limited: 5 attempts per 15 minutes per IP
- Requires old password verification (prevents takeover via session hijacking)
- Validates new password against Django validators
- Prevents password reuse (checks history)
- Invalidates all other sessions
- Tracks in password history
- Logs all attempts
- Sends confirmation email

---

## Security Measures

### Token Security
- **Generation:** Cryptographically secure random tokens (256-bit)
- **Storage:** Tokens hashed with SHA-256 before storing (not plaintext)
- **Expiry:** 1-hour expiration (auto-invalidates old tokens)
- **Single-use:** Marked as used after reset (prevents reuse)
- **Audit Trail:** IP address and user agent logged

### Rate Limiting
- **Password Reset Request:** 3/hour per IP
- **Password Reset Confirm:** 5/15min per IP
- **Password Change:** 5/15min per IP (same as login)

### Email Security
- **No enumeration:** Same message for existing/non-existing emails
- **Secure link:** Token in URL only (can't be intercepted in email body)
- **Clear instructions:** Multiple ways to reset (link or token)
- **Expiry info:** User shown expiration time in email
- **Security notice:** Email warns about contacting support if unauthorized
- **HTML templates:** Professional, branded emails

### Password Validation
- Minimum 8 characters
- Can't be the same as old password
- Checked against common password list (Django default)
- Checked against user information (name, email, etc.)
- No purely numeric passwords

### Password History
- Tracks last 5 passwords per user
- Prevents reuse of recent passwords
- Stored as hashed values (not plaintext)
- Created automatically on password change
- Tracked via password_last_changed timestamp

### Session Management
- All sessions invalidated after password reset
- All sessions invalidated after password change
- Forces re-authentication on all devices
- Uses JWT token blacklist mechanism

### Logging
All password operations are logged with:
- User email
- Operation type (reset, change, failed attempt)
- IP address
- Timestamp
- Success/failure status

---

## Frontend Integration

### Password Reset Flow
1. User navigates to password reset page
2. Enters email address
3. System sends reset email (if account exists)
4. User clicks link or enters token in frontend
5. Frontend validates token via `validate-token/` endpoint
6. User enters new password
7. Frontend sends to `confirm/` endpoint
8. System resets password and sends confirmation email

### Password Change Flow
1. User logs in (has valid token)
2. Navigates to account settings
3. Enters current password and new password
4. Clicks "Change Password"
5. Frontend sends to `password-change/` endpoint
6. System validates and updates password
7. User receives confirmation email

### Token Validation Example
```javascript
// Frontend example
async function validateResetToken(token) {
    const response = await fetch('/api/auth/password-reset/validate-token/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    });
    
    const data = await response.json();
    return data.valid;
}
```

---

## Configuration

### Environment Variables
```bash
FRONTEND_URL=https://frontend.example.com
DEFAULT_FROM_EMAIL=noreply@example.com
```

### Email Settings
Ensure Django email backend is configured:
```python
# settings.py
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'  # or your email provider
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@gmail.com'
EMAIL_HOST_PASSWORD = 'your-app-password'
DEFAULT_FROM_EMAIL = 'noreply@example.com'
```

---

## Error Handling

### Common Scenarios

**1. Token Expired**
- User tries to reset with old token
- System returns 400: "Invalid, expired, or already used token"
- User must request new reset

**2. Token Already Used**
- User clicks reset link twice
- System returns 400: "Invalid, expired, or already used token"
- User must request new reset

**3. Rate Limited**
- User attempts too many reset requests
- System returns 429: "Request was throttled"
- User must wait before trying again

**4. Wrong Old Password**
- User enters incorrect current password during change
- System returns 400: "Old password is incorrect"
- No penalty, can try again

**5. Weak Password**
- User enters password that doesn't meet requirements
- System returns 400 with specific requirement list
- User can try different password

---

## Testing

### Manual Testing Checklist

- [ ] Password reset request with valid email
- [ ] Password reset request with non-existent email (should return same message)
- [ ] Validate token immediately after request
- [ ] Validate token with expired token (wait 1+ hour)
- [ ] Validate token with already-used token
- [ ] Reset password with valid token
- [ ] Try using same token twice (should fail)
- [ ] Attempt reset with weak password
- [ ] Attempt reset with same old password
- [ ] Verify emails received for reset request
- [ ] Verify emails received after successful reset
- [ ] Test rate limiting (>3 requests in 1 hour)
- [ ] Test password change as authenticated user
- [ ] Test password change with wrong old password
- [ ] Verify sessions invalidated after password change
- [ ] Verify password history prevents reuse
- [ ] Check audit logs for all operations

---

## Troubleshooting

### Emails Not Sending
1. Check email backend configuration
2. Verify SMTP credentials
3. Check application logs for email errors
4. Verify sender email is correct
5. Check spam folder (especially Gmail)

### Token Invalid Errors
1. Verify token hasn't expired (1 hour limit)
2. Verify token hasn't been used
3. Verify token format is correct
4. Check if user account is active

### Rate Limit Issues
1. Check IP address (may be behind proxy)
2. Wait for throttle window to pass
3. Verify throttle settings in settings.py

---

## Compliance & Security

- **OWASP:** Follows OWASP authentication best practices
- **GDPR:** No PII stored in tokens
- **Password Security:** Django password validators + custom rules
- **Email Security:** HTML templates with clear instructions
- **Audit Trail:** All operations logged with timestamp, IP, and user
- **Rate Limiting:** Prevents brute force and email bombing
- **Session Management:** JWT with token blacklist

---

## Implementation Details

### Files Modified/Created

1. **apps/authentication/models.py**
   - `PasswordResetToken` model (already exists)

2. **apps/authentication/serializers.py** (NEW)
   - `PasswordResetRequestSerializer`
   - `PasswordResetConfirmSerializer`
   - `PasswordChangeSerializer`

3. **apps/authentication/views.py**
   - `PasswordResetRequestView` (enhanced)
   - `PasswordResetValidateTokenView` (enhanced)
   - `PasswordResetConfirmView` (enhanced)
   - `PasswordChangeView` (NEW)

4. **apps/authentication/email_utils.py** (NEW)
   - `send_password_reset_email()` - HTML formatted
   - `send_password_change_confirmation_email()` - HTML formatted

5. **apps/authentication/urls.py**
   - Added `password-change/` endpoint

6. **apps/authentication/migrations/**
   - 0001_initial.py (PasswordResetToken model)

### Related Files

- **apps/users/models.py** - Password history tracking in User.save()
- **apps/users/popia_models.py** - `PasswordHistory` model
- **pss_backend/throttles.py** - Rate limiting classes
- **pss_backend/validators.py** - Input validation

---

## Future Enhancements

- [ ] Two-factor authentication (2FA)
- [ ] Passwordless authentication (magic links)
- [ ] Password complexity rules UI
- [ ] Password strength meter
- [ ] Security questions backup
- [ ] Recovery codes for 2FA
- [ ] Device fingerprinting
- [ ] Geographic anomaly detection

