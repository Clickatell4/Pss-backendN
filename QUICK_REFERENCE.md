# Password Reset Quick Reference Guide

## Quick Start for Developers

### Testing Password Reset Locally

```bash
# 1. Start Django shell
python manage.py shell

# 2. Create a test user
from django.contrib.auth import get_user_model
User = get_user_model()
user = User.objects.create_user(
    email='test@capaciti.org.za',
    password='TestPassword123!',
    first_name='Test'
)

# 3. Generate a reset token
from apps.authentication.models import PasswordResetToken
token_string, token_obj = PasswordResetToken.generate_token(user)
print(f"Reset Token: {token_string}")
print(f"Token expires at: {token_obj.expires_at}")

# 4. Test token validation
verified = PasswordResetToken.verify_token(token_string)
print(f"Token valid: {verified is not None}")

# 5. Mark token as used
token_obj.mark_as_used()
print(f"Token marked as used")
```

### Testing with API Client

```bash
# 1. Request password reset
curl -X POST http://localhost:8000/api/auth/password-reset/request/ \
  -H "Content-Type: application/json" \
  -d '{"email":"test@capaciti.org.za"}'

# Response:
# {
#   "message": "If an account with that email exists...",
#   "detail": "Please check your email for instructions."
# }

# 2. Validate token (replace with actual token from email)
curl -X POST http://localhost:8000/api/auth/password-reset/validate-token/ \
  -H "Content-Type: application/json" \
  -d '{"token":"actual_token_here"}'

# 3. Confirm password reset
curl -X POST http://localhost:8000/api/auth/password-reset/confirm/ \
  -H "Content-Type: application/json" \
  -d '{
    "token":"actual_token_here",
    "new_password":"NewSecurePassword123!"
  }'

# 4. Change password (requires auth token)
curl -X POST http://localhost:8000/api/auth/password-change/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password":"CurrentPassword123!",
    "new_password":"NewPassword123!@#"
  }'
```

### Email Configuration for Testing

**Using MailHog (Recommended for Local Development):**
```python
# settings.py
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'  # In-memory
# OR
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'  # Print to console
```

**Using Gmail/Real SMTP:**
```python
# .env
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password  # Not your Gmail password!
DEFAULT_FROM_EMAIL=noreply@yourapp.com
```

**Get Gmail App Password:**
1. Enable 2FA in Google Account
2. Go to Security → App passwords
3. Select Mail & Windows Computer
4. Generate password
5. Use this password in EMAIL_HOST_PASSWORD

### Common Issues & Solutions

#### Issue: "Email not found" when requesting reset
**Solution:** Check if email domain validation is enabled. Ensure email is @capaciti.org.za

#### Issue: Token always invalid
**Solution:** 
1. Check token hasn't expired (1-hour limit)
2. Verify token hash hasn't been modified
3. Check if token already used

#### Issue: Emails not being sent
**Solution:**
1. Verify EMAIL_BACKEND configuration
2. Check SMTP credentials
3. Look for exceptions in logs: `tail -f logs/django.log`
4. Test email backend: `python manage.py shell < test_email.py`

#### Issue: Rate limit reached
**Solution:** Wait for throttle window (3/hour = 20 minutes between attempts)

### Debug Logging

Enable debug logging for password operations:

```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django.security.auth': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

Then check logs for password operations:
```bash
# Watch logs in real-time
tail -f logs/django.log | grep "Password"
```

### Running Tests

```bash
# Run all password reset/change tests
pytest apps/authentication/tests.py -v

# Run specific test
pytest apps/authentication/tests.py::PasswordResetTestCase::test_password_reset_request_valid_email -v

# Run with coverage
pytest apps/authentication/tests.py --cov=apps.authentication --cov-report=html

# Run and show output
pytest apps/authentication/tests.py -v -s
```

### Database Queries for Debugging

```python
# Check all reset tokens for a user
from django.contrib.auth import get_user_model
from apps.authentication.models import PasswordResetToken
from django.utils import timezone

User = get_user_model()
user = User.objects.get(email='test@capaciti.org.za')

# Find valid tokens
valid_tokens = PasswordResetToken.objects.filter(
    user=user,
    used=False,
    expires_at__gt=timezone.now()
)
print(f"Valid tokens: {valid_tokens.count()}")

# Find all tokens for user
all_tokens = PasswordResetToken.objects.filter(user=user).order_by('-created_at')
for token in all_tokens:
    status = "used" if token.used else ("expired" if token.expires_at < timezone.now() else "valid")
    print(f"Token: {token.token_hash[:10]}... ({status})")

# Check password history
from apps.users.popia_models import PasswordHistory
history = PasswordHistory.objects.filter(user=user).order_by('-created_at')
print(f"Password history entries: {history.count()}")
for entry in history:
    print(f"  - Changed at: {entry.created_at}")
```

### API Response Status Codes

| Status | Meaning | Action |
|--------|---------|--------|
| 200 | Success | Operation completed |
| 400 | Bad Request | Check request data, invalid input |
| 401 | Unauthorized | Authentication required for this endpoint |
| 429 | Rate Limited | Wait before retrying |
| 500 | Server Error | Check server logs |

### Password Requirements

- **Minimum length:** 8 characters
- **Must include:**
  - Uppercase letter (A-Z)
  - Lowercase letter (a-z)
  - Number (0-9)
- **Avoid:**
  - Common passwords (password123, qwerty, etc.)
  - Username or email in password
  - Same as previous password

### Security Checklist

- [ ] FRONTEND_URL environment variable set correctly
- [ ] DEFAULT_FROM_EMAIL configured
- [ ] Email backend configured (SMTP or test backend)
- [ ] HTTPS enabled in production
- [ ] SECRET_KEY different from development
- [ ] DEBUG=False in production
- [ ] Rate limiting enabled (default is on)
- [ ] Password validators configured
- [ ] Logs monitored for security events
- [ ] Email templates reviewed for branding
- [ ] SSL/TLS enabled for email (SMTP)

### Performance Considerations

- **Token generation:** ~1-2ms (uses secrets module)
- **Token verification:** ~5-10ms (hash lookup)
- **Email sending:** 500-5000ms (depends on email provider)
- **Database queries:** <10ms per operation
- **Rate limiting:** <1ms (in-memory check)

### Monitoring & Alerts

Log entries to monitor:
```
- "Password reset requested for"
- "Password reset successful for"
- "Password changed successfully for"
- "Invalid/expired password reset token attempted"
- "Password change validation failed"
- "Failed to send password reset email"
```

Set up alerts for:
- Multiple failed reset attempts (>5 in 1 hour)
- Multiple failed password change attempts
- Email sending failures
- Rate limit exceeded events

### Frontend Integration Example (JavaScript)

```javascript
// Request password reset
async function requestPasswordReset(email) {
    const response = await fetch('/api/auth/password-reset/request/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
    });
    return await response.json();
}

// Validate reset token
async function validateResetToken(token) {
    const response = await fetch('/api/auth/password-reset/validate-token/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    });
    const data = await response.json();
    return data.valid;
}

// Confirm password reset
async function confirmPasswordReset(token, newPassword) {
    const response = await fetch('/api/auth/password-reset/confirm/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            token: token,
            new_password: newPassword
        })
    });
    return await response.json();
}

// Change password (authenticated)
async function changePassword(oldPassword, newPassword, accessToken) {
    const response = await fetch('/api/auth/password-change/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({
            old_password: oldPassword,
            new_password: newPassword
        })
    });
    return await response.json();
}
```

### Support & Documentation

- Full API documentation: `PASSWORD_RESET_IMPLEMENTATION.md`
- Implementation summary: `IMPLEMENTATION_SUMMARY.md`
- Test suite: `apps/authentication/tests.py`
- Email templates: `apps/authentication/email_utils.py`
- Django logs: Check `logs/django.log`
