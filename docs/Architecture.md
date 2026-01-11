# PSS Backend - Architecture Overview

## System Overview

The PSS (Personal Support System) Backend is a Django REST Framework API that provides secure data management for CAPACITI students with disabilities. It handles authentication, user profiles, medical information, journal entries, and administrative notes.

## High-Level Architecture

```
┌─────────────────────────────────────────────────┐
│         React Frontend (Vite + React)           │
│         http://localhost:5173 (dev)             │
│         https://pss-frontend.com (prod)         │
└─────────────────┬───────────────────────────────┘
                  │ HTTPS + CORS
                  │ JWT Tokens (Authorization: Bearer)
                  ↓
┌─────────────────────────────────────────────────┐
│         Nginx Reverse Proxy (Production)        │
│         Port 443 → 8000                          │
│         SSL/TLS Termination                      │
└─────────────────┬───────────────────────────────┘
                  │
                  ↓
┌─────────────────────────────────────────────────┐
│       Django REST API (Gunicorn Workers)        │
│       http://localhost:8000 (dev)                │
│       https://pss-backend.onrender.com (prod)   │
├─────────────────────────────────────────────────┤
│  Django Apps:                                   │
│  ├─ authentication/  JWT login/logout/refresh   │
│  ├─ users/          User & profile management   │
│  ├─ intake/         Intake form processing      │
│  ├─ journal/        Journal entries CRUD        │
│  ├─ admin_notes/    Admin notes on candidates   │
│  └─ dashboard/      Statistics & analytics      │
├─────────────────────────────────────────────────┤
│  Middleware:                                    │
│  ├─ CORS (django-cors-headers)                  │
│  ├─ JWT Authentication (SimpleJWT)              │
│  ├─ Django Axes (Brute-force protection)        │
│  └─ Security Headers                            │
└─────────────────┬───────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
        ↓                   ↓
┌──────────────┐    ┌──────────────┐
│ PostgreSQL   │    │  Redis       │
│ (Neon)       │    │  (Planned)   │
│ Port 5432    │    │  Port 6379   │
│ Pooler Mode  │    │              │
└──────────────┘    └──────────────┘
```

## Technology Stack

### Core Framework
- **Django 4.2.7**: Web framework
- **Django REST Framework 3.14.0**: API framework
- **Python 3.11+**: Programming language

### Database
- **PostgreSQL 16+**: Primary database
- **Neon Serverless**: Cloud PostgreSQL (production)
- **Connection Pooling**: PgBouncer mode

### Authentication & Security
- **djangorestframework-simplejwt 5.3.0**: JWT authentication
- **django-cors-headers**: CORS handling
- **django-axes**: Brute-force protection
- **cryptography** (planned): Field-level encryption

### Production Server
- **Gunicorn 21.2.0**: WSGI HTTP server
- **Render**: Cloud platform (current)

### Planned Additions
- **Redis**: Caching and session storage
- **Celery**: Asynchronous task processing
- **Sentry**: Error tracking and monitoring
- **django-filter**: Advanced filtering

## Django Project Structure

```
Pss-backendN/
├── apps/                          # Django applications
│   ├── admin_notes/
│   │   ├── models.py             # AdminNote model
│   │   ├── serializers.py        # AdminNote serializers
│   │   ├── views.py              # AdminNote API views
│   │   ├── urls.py               # AdminNote URL routing
│   │   └── permissions.py        # AdminNote permissions
│   │
│   ├── authentication/
│   │   ├── views.py              # Login, logout, refresh, register
│   │   ├── serializers.py        # Auth serializers
│   │   └── urls.py               # Auth URL routing
│   │
│   ├── dashboard/
│   │   ├── views.py              # Dashboard statistics
│   │   └── urls.py               # Dashboard routing
│   │
│   ├── intake/
│   │   ├── models.py             # IntakeForm model
│   │   ├── serializers.py        # Intake serializers
│   │   ├── views.py              # Intake submission/retrieval
│   │   └── urls.py               # Intake routing
│   │
│   ├── journal/
│   │   ├── models.py             # JournalEntry model
│   │   ├── serializers.py        # Journal serializers
│   │   ├── views.py              # Journal CRUD views
│   │   └── urls.py               # Journal routing
│   │
│   └── users/
│       ├── models.py             # User, UserProfile models
│       ├── managers.py           # Custom user manager
│       ├── serializers.py        # User serializers
│       ├── views.py              # User CRUD views
│       ├── permissions.py        # IsAdminOrSelf permission
│       └── urls.py               # User routing
│
├── config/                       # Project configuration
│   ├── settings.py              # Django settings
│   ├── urls.py                  # Root URL configuration
│   ├── wsgi.py                  # WSGI application
│   └── asgi.py                  # ASGI application (future)
│
├── manage.py                    # Django management script
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variables template
├── render.yaml                  # Render deployment config
└── README.md                    # Project README
```

## Database Schema

### User Model (Custom)

```python
class User(AbstractBaseUser, PermissionsMixin):
    email = EmailField(unique=True)           # Primary identifier
    first_name = CharField(max_length=150)
    last_name = CharField(max_length=150)
    role = CharField(choices=ROLE_CHOICES)    # candidate, admin, superuser
    is_active = BooleanField(default=True)
    is_staff = BooleanField(default=False)
    date_joined = DateTimeField(auto_now_add=True)

    # Relationships
    profile = OneToOneField('UserProfile')
```

### UserProfile Model

```python
class UserProfile(models.Model):
    user = OneToOneField(User, on_delete=CASCADE)

    # Personal Information
    date_of_birth = DateField(null=True, blank=True)
    phone_number = CharField(max_length=15)
    address = TextField(blank=True)

    # Sensitive Medical Information (⚠️ NEEDS ENCRYPTION - SCRUM-6)
    id_number = CharField(max_length=13)      # SA ID number
    diagnosis = TextField()                    # Medical diagnosis
    medications = TextField()                  # Current medications
    allergies = TextField()                    # Known allergies
    doctor_name = CharField(max_length=255)
    doctor_phone = CharField(max_length=15)
    medical_notes = TextField()

    # Emergency Contact
    emergency_contact_name = CharField(max_length=255)
    emergency_contact_phone = CharField(max_length=15)
    emergency_contact_relationship = CharField(max_length=100)

    # Intake Status
    has_completed_intake = BooleanField(default=False)
```

### JournalEntry Model

```python
class JournalEntry(models.Model):
    user = ForeignKey(User, on_delete=CASCADE)
    date = DateField(auto_now_add=True)
    title = CharField(max_length=255)
    content = TextField()

    # Mood Tracking
    mood = CharField(max_length=20, choices=MOOD_CHOICES)
    energy_level = IntegerField(validators=[MinValueValidator(1),
                                           MaxValueValidator(10)])

    # Metadata
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)
```

### AdminNote Model

```python
class AdminNote(models.Model):
    candidate = ForeignKey(User, on_delete=CASCADE,
                          related_name='admin_notes')
    admin = ForeignKey(User, on_delete=CASCADE,
                      related_name='created_notes')
    note_text = TextField()
    tags = CharField(max_length=255, blank=True)  # Comma-separated
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)
```

### IntakeForm Model

```python
class IntakeForm(models.Model):
    user = ForeignKey(User, on_delete=CASCADE)

    # Form Responses (JSON field)
    responses = JSONField()  # Stores all intake form answers

    # Metadata
    submitted_at = DateTimeField(auto_now_add=True)
    status = CharField(max_length=20, default='submitted')
```

## Database Relationships

```
User (1) ─────────── (1) UserProfile
  │
  ├─── (1:N) ─────── JournalEntry
  │
  ├─── (1:N) ─────── AdminNote (as candidate)
  │
  ├─── (1:N) ─────── AdminNote (as admin)
  │
  └─── (1:N) ─────── IntakeForm
```

## API Architecture

### REST API Design

All API endpoints follow RESTful conventions:

- **Base URL**: `/api/`
- **Version**: v1 (planned - see SCRUM-36)
- **Authentication**: JWT Bearer tokens
- **Content-Type**: `application/json`
- **Response Format**: JSON

### Authentication Flow

```
1. Register/Login
   POST /api/auth/register/  OR  POST /api/auth/login/
   → Returns: { access_token, refresh_token }

2. Access Protected Endpoint
   GET /api/users/me/
   Headers: Authorization: Bearer <access_token>
   → Returns: User data

3. Token Expires (15 minutes default)
   → 401 Unauthorized

4. Refresh Token
   POST /api/auth/refresh/
   Body: { refresh: <refresh_token> }
   → Returns: { access: <new_access_token> }

5. Logout
   POST /api/auth/logout/
   Body: { refresh: <refresh_token> }
   → Blacklists refresh token
```

### Permission System

```python
# Permission Classes

IsAuthenticated          # Must have valid JWT token
IsAdminOrSelf           # Custom: Admin or accessing own data
IsAdminUser             # Must be admin or superuser
IsSuperUser             # Must be superuser
```

### API Endpoints Overview

| Endpoint | Method | Permission | Description |
|----------|--------|-----------|-------------|
| `/api/auth/login/` | POST | AllowAny | User login |
| `/api/auth/logout/` | POST | IsAuthenticated | User logout |
| `/api/auth/refresh/` | POST | AllowAny | Refresh token |
| `/api/auth/register/` | POST | AllowAny | User registration |
| `/api/users/` | GET | IsAdminUser | List all users |
| `/api/users/<id>/` | GET/PUT | IsAdminOrSelf | User detail/update |
| `/api/users/<id>/profile/` | GET/PUT | IsAdminOrSelf | Profile detail/update |
| `/api/intake/submit/` | POST | IsAuthenticated | Submit intake form |
| `/api/journal/` | GET/POST | IsAuthenticated | List/create journal |
| `/api/journal/<id>/` | GET/PUT/DELETE | IsAuthenticated | Journal detail |
| `/api/admin-notes/` | GET/POST | IsAdminUser | List/create notes |
| `/api/admin-notes/<id>/` | GET/PUT/DELETE | IsAdminUser | Note detail |
| `/api/dashboard/stats/` | GET | IsAdminUser | Dashboard stats |

See [API Documentation](./API-Documentation.md) for complete details.

## Security Architecture

### Authentication & Authorization

1. **JWT Tokens**
   - Access token: 15 minutes lifetime
   - Refresh token: 7 days lifetime
   - Token rotation on refresh
   - Blacklist on logout

2. **Role-Based Access Control**
   - **Candidate**: Can only access own data
   - **Admin**: Can access all candidate data
   - **Superuser**: Full system access

3. **Permission Checks**
   - View-level permissions
   - Object-level permissions (IsAdminOrSelf)
   - Field-level permissions (planned)

### Data Protection

⚠️ **CRITICAL - NOT YET IMPLEMENTED** (SCRUM-6)

Sensitive fields requiring encryption:
- `id_number`
- `diagnosis`
- `medications`
- `allergies`
- `medical_notes`

### Security Headers

Configured in production:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (planned)

### CORS Configuration

```python
CORS_ALLOWED_ORIGINS = [
    'http://localhost:5173',  # Frontend dev
    'https://pss-frontend.com',  # Frontend prod
]

CORS_ALLOW_CREDENTIALS = True
```

## Data Flow Examples

### User Registration Flow

```
1. Frontend → POST /api/auth/register/
   Body: { email, password, first_name, last_name, role }

2. Backend validates:
   - Email unique
   - Password strength
   - Role permissions

3. Create User + UserProfile
   - Hash password
   - Generate profile

4. Return JWT tokens
   → { access, refresh, user }

5. Frontend stores tokens
   - LocalStorage or HttpOnly cookie
```

### Journal Entry Creation

```
1. Frontend → POST /api/journal/
   Headers: Authorization: Bearer <access_token>
   Body: { title, content, mood, energy_level }

2. Backend:
   - Verify JWT token
   - Extract user from token
   - Validate data

3. Create JournalEntry
   - Associate with user
   - Set timestamps

4. Return created entry
   → { id, title, content, date, ... }
```

## Performance Considerations

### Current Performance

- Average response time: ~200-300ms
- Database queries: N+1 issues exist (see SCRUM-19)
- No caching implemented
- No async task processing

### Optimization Plan

1. **Database** (SCRUM-19)
   - Add indexes on foreign keys
   - Implement `select_related()` and `prefetch_related()`
   - Connection pooling (already configured)

2. **Caching** (SCRUM-33)
   - Redis for session storage
   - Cache user profiles (10 min)
   - Cache dashboard stats (5 min)

3. **Async Tasks** (SCRUM-34)
   - Email sending
   - Data export generation
   - Report generation

## Deployment Architecture

### Current (Render)

```
Render Service
├── Web Service (Gunicorn)
│   ├── Auto-deploy from main branch
│   ├── Health checks: /health/
│   └── Environment variables from dashboard
│
└── PostgreSQL (Neon)
    ├── Serverless PostgreSQL
    ├── Connection pooling enabled
    └── Automatic backups (Neon manages)
```

### Environment Variables

Required in production:
```bash
SECRET_KEY=<django-secret-key>
DEBUG=False
ALLOWED_HOSTS=pss-backend.onrender.com
DATABASE_URL=postgres://...
CORS_ALLOWED_ORIGINS=https://pss-frontend.com
JWT_SECRET_KEY=<jwt-secret-key>
```

## Future Architecture Enhancements

### Planned Additions

1. **Redis Layer**
   - Session storage
   - Caching
   - Rate limiting

2. **Celery Workers**
   - Background tasks
   - Scheduled tasks (Celery Beat)
   - Task monitoring (Flower)

3. **Monitoring**
   - Sentry for error tracking
   - Prometheus for metrics
   - Grafana for dashboards

4. **API Versioning**
   - URL-based versioning (/api/v1/, /api/v2/)
   - Deprecation warnings
   - Version-specific serializers

## Development vs Production

| Feature | Development | Production |
|---------|-------------|------------|
| **DEBUG** | True | False |
| **Database** | SQLite/Local Postgres | Neon Serverless |
| **ALLOWED_HOSTS** | ['*'] | Specific domains |
| **CORS** | Permissive | Restricted |
| **Static Files** | Django serves | Nginx/CDN |
| **Logging** | Console | File + Sentry |
| **HTTPS** | Optional | Required |

## Troubleshooting

### Common Architecture Issues

1. **Database Connection Issues**
   - Check DATABASE_URL format
   - Verify pooler settings (Session Mode for Django)
   - Check SSL requirements

2. **CORS Errors**
   - Verify CORS_ALLOWED_ORIGINS
   - Check request headers
   - Ensure credentials setting

3. **JWT Authentication Fails**
   - Check token format (Bearer <token>)
   - Verify token not expired
   - Check JWT_SECRET_KEY matches

---

**Last Updated**: January 11, 2026
**Version**: 2.0
