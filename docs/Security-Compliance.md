# PSS Backend - Security & POPIA Compliance Guide

## Overview

The PSS Backend handles highly sensitive personal and medical information for students with disabilities. This guide outlines security requirements, POPIA (Protection of Personal Information Act) compliance, and implementation guidelines.

⚠️ **CRITICAL**: This system is subject to South African data protection laws (POPIA). Non-compliance can result in fines up to R10 million.

## Sensitive Data Categories

### Personal Identifiable Information (PII)
- South African ID numbers
- Full names
- Email addresses
- Phone numbers
- Physical addresses
- Date of birth (derived from ID number)

### Medical Information (Special Personal Information under POPIA)
- Medical diagnoses
- Disability information
- Current medications
- Allergies
- Doctor information
- Medical notes

### Emergency Contacts
- Names
- Phone numbers
- Relationships

### Behavioral Data
- Journal entries (may contain sensitive content)
- Mood tracking data
- Admin notes (staff observations)

## POPIA Requirements

### 1. Lawfulness of Processing

**Requirement**: Process personal information lawfully and reasonably.

**Implementation**:
- ✅ Clear purpose for data collection
- ✅ User consent during registration
- ⚠️ Privacy policy acceptance (NEEDS IMPLEMENTATION - see GitHub issues)
- ⚠️ Terms of service acceptance

### 2. Processing Limitation

**Requirement**: Process only for specified, lawful purpose.

**Implementation**:
- ✅ Data collected only for PSS system purpose
- ✅ Role-based access control limits who can access what
- ❌ Data minimization audit needed (SCRUM-118)

### 3. Purpose Specification

**Requirement**: Collection must be for specific, lawful purpose.

**Current Purposes**:
- Medical support coordination
- Student wellness tracking
- Administrative support notes
- Emergency contact information
- Service improvement

### 4. Further Processing Limitation

**Requirement**: Don't use data for incompatible purposes.

**Implementation**:
- ✅ No data sharing with third parties
- ✅ No marketing use
- ❌ Need explicit consent management system

### 5. Information Quality

**Requirement**: Keep data complete, accurate, not misleading, and updated.

**Implementation**:
- ✅ Users can update their own profiles
- ✅ Validation on input
- ⚠️ Data quality checks needed
- ⚠️ Automated data archival (SCRUM-43)

### 6. Openness

**Requirement**: Inform data subjects about processing.

**Implementation Status**:
- ⚠️ Privacy policy (NEEDS IMPLEMENTATION)
- ⚠️ Data processing notice
- ⚠️ Cookie policy
- ✅ Clear purpose in intake form

### 7. Security Safeguards

**Requirement**: Secure personal information against loss, damage, unauthorized access.

**Implementation**:
- ✅ HTTPS in production
- ✅ Password hashing (bcrypt)
- ✅ JWT authentication
- ❌ **CRITICAL**: Field-level encryption (SCRUM-6)
- ⚠️ Audit logging (SCRUM-8)
- ⚠️ Rate limiting (needs improvement)
- ⚠️ Brute-force protection (Django Axes enabled)

### 8. Data Subject Participation

**Requirement**: Data subjects can access, correct, and request deletion.

**Current Status**:
- ✅ Users can view their data
- ✅ Users can update profiles
- ❌ Data export functionality (SCRUM-32)
- ❌ Account deletion functionality
- ❌ Data correction requests

## Critical Security Issues

### 🔴 CRITICAL: Unencrypted PII (GitHub Issue TBD)

**Status**: NOT IMPLEMENTED

**Risk**: POPIA violation, data breach exposure

**Affected Fields**:
```python
# UserProfile model
id_number           # SA ID number (contains DOB, gender)
diagnosis          # Medical diagnosis
medications        # Current medications
allergies          # Known allergies
doctor_name        # Healthcare provider
doctor_phone       # Healthcare contact
medical_notes      # Detailed medical information
```

**Required Implementation**:

1. Install encryption library:
```bash
pip install django-fernet-fields
```

2. Update models:
```python
from fernet_fields import EncryptedTextField, EncryptedCharField

class UserProfile(models.Model):
    # Encrypted fields
    id_number = EncryptedCharField(max_length=13)
    diagnosis = EncryptedTextField()
    medications = EncryptedTextField()
    allergies = EncryptedTextField()
    medical_notes = EncryptedTextField()
```

3. Set encryption key in `.env`:
```bash
ENCRYPTION_KEY=<generate-with-cryptography.fernet>
```

4. Data migration strategy:
   - Backup database
   - Create migration
   - Encrypt existing data
   - Test thoroughly
   - Deploy

**Priority**: MUST FIX BEFORE PRODUCTION

---

### 🔴 CRITICAL: Missing Audit Logging (GitHub Issue TBD)

**Status**: PARTIALLY IMPLEMENTED

**Risk**: Cannot prove POPIA compliance, no breach detection

**Required Actions**:

1. Log all access to sensitive data:
```python
# Example audit log model
class AuditLog(models.Model):
    user = ForeignKey(User)
    action = CharField()  # 'view', 'create', 'update', 'delete'
    resource_type = CharField()  # 'UserProfile', 'JournalEntry'
    resource_id = IntegerField()
    timestamp = DateTimeField(auto_now_add=True)
    ip_address = GenericIPAddressField()
    user_agent = TextField()
```

2. Implement audit middleware:
```python
class AuditMiddleware:
    def __call__(self, request):
        # Log all sensitive data access
        if request.path.startswith('/api/users/'):
            AuditLog.objects.create(
                user=request.user,
                action=request.method,
                resource_type='User',
                ip_address=get_client_ip(request),
                ...
            )
```

3. Retention: Keep audit logs for 7 years (POPIA requirement)

**Priority**: MUST FIX BEFORE PRODUCTION

---

### 🟡 HIGH: Weak Password Policy

**Current**: Default Django password validation

**Required**:
- Minimum 12 characters
- Uppercase + lowercase + numbers + special characters
- No common passwords
- No personal information
- Password history (prevent reuse of last 5)
- Password expiry (90 days for admins)

**Implementation**:
```python
# settings.py
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12}
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    # Add custom validator for complexity
]
```

---

### 🟡 HIGH: Insufficient Rate Limiting

**Current**: Basic DRF throttling

**Required**:
- Login endpoint: 5 attempts per 15 minutes
- Registration: 3 attempts per hour
- Password reset: 3 attempts per hour
- API endpoints: 100 requests per minute

**Implementation**:
```python
# Use django-axes (already installed)
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=15)
AXES_LOCKOUT_CALLABLE = 'apps.users.lockout.lockout_response'
```

---

## Security Best Practices

### 1. Authentication

**JWT Token Security**:
```python
# settings.py
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': env('JWT_SECRET_KEY'),
    'AUTH_HEADER_TYPES': ('Bearer',),
}
```

**Best Practices**:
- ✅ Short-lived access tokens (15 minutes)
- ✅ Refresh token rotation
- ✅ Token blacklisting on logout
- ⚠️ Token storage: Use HttpOnly cookies (frontend)
- ⚠️ CSRF protection with tokens

### 2. Authorization

**Role-Based Access Control**:
```python
# Permission hierarchy
Superuser > Admin > Candidate

# Permission classes
IsAuthenticated       # All authenticated users
IsAdminUser          # Admin + Superuser only
IsAdminOrSelf        # Admin or accessing own data
IsSuperUser          # Superuser only
```

**Best Practices**:
- ✅ Principle of least privilege
- ✅ Object-level permissions
- ⚠️ Need field-level permissions for sensitive data

### 3. Input Validation

**Always Validate**:
- Email format
- Phone number format
- SA ID number format (13 digits, valid checksum)
- Date formats
- File uploads (type, size, content)

**Serializer Validation**:
```python
class UserProfileSerializer(serializers.ModelSerializer):
    def validate_id_number(self, value):
        if not validate_sa_id(value):
            raise serializers.ValidationError("Invalid SA ID number")
        return value
```

**Never Trust Client Input**:
- Sanitize all text input
- Validate all numeric input
- Check file types and sizes
- Prevent SQL injection (use ORM)
- Prevent XSS (escape output)

### 4. Data Protection

**Encryption at Rest**:
- ❌ Field-level encryption (MUST IMPLEMENT)
- ✅ Database connection encryption (SSL)
- ⚠️ Backup encryption

**Encryption in Transit**:
- ✅ HTTPS only in production
- ✅ Secure WebSocket (WSS) if needed
- ✅ SSL/TLS 1.2 minimum

**Data Minimization**:
```python
# Only collect what's necessary
# Example: DOB can be derived from ID number
@property
def date_of_birth(self):
    return extract_dob_from_id(self.id_number)
```

### 5. Session Management

**Current**:
- JWT stateless authentication
- No server-side sessions

**Planned** (with Redis):
- Session storage in Redis
- Session timeout: 15 minutes idle
- Concurrent session limits
- Session invalidation on logout

### 6. Error Handling

**DO NOT expose sensitive info in errors**:

❌ Bad:
```python
return Response({
    'error': f'User {user.email} not found in database table users'
})
```

✅ Good:
```python
return Response({
    'error': 'Invalid credentials'
}, status=401)
```

**Log errors securely**:
- Log to file, not console in production
- Sanitize logs (no passwords, tokens)
- Use Sentry for error tracking
- Rotate logs regularly

### 7. API Security

**Security Headers**:
```python
# settings.py
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_SSL_REDIRECT = True  # Production only
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
```

**CORS Configuration**:
```python
CORS_ALLOWED_ORIGINS = [
    'https://pss-frontend.com',
]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
```

## POPIA Compliance Checklist

### Data Collection

- [ ] Privacy policy published and accepted
- [ ] Terms of service published and accepted
- [ ] Clear purpose specified for data collection
- [ ] Minimal data collection (only what's necessary)
- [ ] User consent obtained and recorded
- [ ] Cookie policy (if applicable)

### Data Storage

- [x] Secure storage (database)
- [ ] Field-level encryption for sensitive data
- [x] Access controls (role-based)
- [ ] Audit logging for all access
- [ ] Data backup strategy
- [ ] Backup encryption

### Data Access

- [x] Role-based access control
- [x] Authentication required
- [ ] Audit trail of who accessed what
- [ ] IP address logging
- [ ] Failed access attempt monitoring

### Data Subject Rights

- [x] Users can view their data
- [x] Users can update their data
- [ ] Users can export their data (SCRUM-32)
- [ ] Users can request data deletion
- [ ] Users can request data correction
- [ ] Response to requests within 30 days

### Data Retention

- [ ] Retention policy defined (SCRUM-43)
- [ ] Automated data archival
- [ ] Automated data deletion
- [ ] Audit logs retained for 7 years
- [ ] User data deleted on account closure

### Data Security

- [x] HTTPS in production
- [ ] Field-level encryption
- [x] Password hashing
- [ ] Comprehensive audit logging
- [ ] Rate limiting and brute-force protection
- [ ] Security monitoring and alerts

### Data Breach Response

- [ ] Breach detection mechanisms
- [ ] Incident response plan documented
- [ ] Breach notification procedures
- [ ] Contact: Information Regulator within 72 hours
- [ ] Contact: Affected users promptly

### Compliance Documentation

- [ ] Privacy policy
- [ ] Data processing agreement
- [ ] Consent records
- [ ] Audit logs (7-year retention)
- [ ] Security measures documentation
- [ ] Data flow diagrams

## Security Monitoring

### Required Monitoring (Not Yet Implemented)

1. **Error Tracking** (Sentry)
   - Track all exceptions
   - Alert on critical errors
   - Monitor error rates

2. **Access Monitoring**
   - Failed login attempts
   - Unusual access patterns
   - Permission violations
   - Data export requests

3. **Performance Monitoring**
   - Response times
   - Database query performance
   - API endpoint usage

4. **Security Monitoring**
   - Brute-force attempts
   - Suspicious IP addresses
   - Unusual data access patterns
   - Multiple concurrent sessions

### Alerts Required

- Multiple failed logins
- Access to sensitive data
- Unusual access times
- Data export requests
- System errors
- Database connection issues
- Performance degradation

## Incident Response Plan

### Data Breach Response

1. **Detection** (< 1 hour)
   - Monitor alerts
   - Review logs
   - Identify scope

2. **Containment** (< 4 hours)
   - Isolate affected systems
   - Revoke compromised credentials
   - Block unauthorized access

3. **Assessment** (< 24 hours)
   - Determine what data was accessed
   - Identify affected users
   - Document timeline

4. **Notification** (< 72 hours)
   - Report to Information Regulator
   - Notify affected users
   - Public statement if required

5. **Recovery**
   - Restore from backups if needed
   - Patch vulnerabilities
   - Enhanced monitoring

6. **Post-Incident**
   - Root cause analysis
   - Update security measures
   - Staff training
   - Policy updates

## Production Security Checklist

Before deploying to production:

### Django Settings
- [ ] `DEBUG = False`
- [ ] Strong `SECRET_KEY` (50+ characters)
- [ ] Specific `ALLOWED_HOSTS`
- [ ] `SECURE_SSL_REDIRECT = True`
- [ ] `SESSION_COOKIE_SECURE = True`
- [ ] `CSRF_COOKIE_SECURE = True`
- [ ] Security headers configured

### Database
- [ ] Strong database password
- [ ] SSL connection required
- [ ] Connection pooling configured
- [ ] Automated backups enabled
- [ ] Backup encryption enabled

### Authentication
- [ ] JWT secrets different from dev
- [ ] Token rotation enabled
- [ ] Token blacklisting enabled
- [ ] Rate limiting configured
- [ ] 2FA enabled for admins

### Sensitive Data
- [ ] Field-level encryption implemented
- [ ] Encryption keys secured
- [ ] Key rotation strategy
- [ ] No secrets in code
- [ ] Environment variables secured

### Monitoring
- [ ] Sentry configured
- [ ] Logging configured
- [ ] Alerts configured
- [ ] Health checks working
- [ ] Uptime monitoring enabled

### Compliance
- [ ] Privacy policy published
- [ ] Terms of service published
- [ ] Consent management working
- [ ] Data export functionality
- [ ] Audit logging enabled

## Resources

### POPIA Resources
- [POPIA Act](https://popia.co.za/)
- [Information Regulator SA](https://www.justice.gov.za/inforeg/)
- [POPIA Compliance Guide](https://popia.co.za/compliance-guide/)

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Django Security](https://docs.djangoproject.com/en/4.2/topics/security/)
- [DRF Security](https://www.django-rest-framework.org/topics/security/)

### Internal Documentation
- [Architecture Overview](./Architecture.md)
- [Development Setup](./Development-Setup.md)
- [Handover Roadmap](./Handover-Roadmap.md)

---

**Last Updated**: January 11, 2026
**Version**: 2.0
**Review Schedule**: Monthly
**Next Review**: February 11, 2026
