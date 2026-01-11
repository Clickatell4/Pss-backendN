# PSS Backend - Development Setup Guide

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.11+** ([Download](https://www.python.org/downloads/))
- **PostgreSQL 16+** ([Download](https://www.postgresql.org/download/)) OR use Neon serverless
- **Git** ([Download](https://git-scm.com/downloads))
- **pip** (comes with Python)
- **virtualenv** or **venv** (Python virtual environment)

### Recommended Tools

- **VS Code** with Python extension
- **Postman** or **Thunder Client** for API testing
- **pgAdmin** or **TablePlus** for database management
- **GitHub Desktop** (optional)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Clickatell4/Pss-backendN.git
cd Pss-backendN
```

### 2. Create Virtual Environment

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

You should see `(venv)` in your terminal prompt.

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs:
- Django 4.2.7
- Django REST Framework
- SimpleJWT
- psycopg2 (PostgreSQL adapter)
- django-cors-headers
- django-axes
- Other dependencies

### 4. Set Up Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```bash
# Django Settings
SECRET_KEY=your-secret-key-here-change-this-in-production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Settings (Local PostgreSQL)
DATABASE_URL=postgresql://username:password@localhost:5432/pss_backend

# OR use Neon serverless (recommended for dev)
# DATABASE_URL=postgresql://username:password@aws-0-us-east-1.pooler.neon.tech/pss_db?sslmode=require

# CORS Settings
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000

# JWT Settings
JWT_SECRET_KEY=your-jwt-secret-key-here-change-this
JWT_ACCESS_TOKEN_LIFETIME=15  # minutes
JWT_REFRESH_TOKEN_LIFETIME=7  # days
```

**⚠️ IMPORTANT**: Never commit the `.env` file to Git!

### 5. Set Up Database

#### Option A: Local PostgreSQL

Create a new database:
```bash
# Login to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE pss_backend;

# Create user (optional)
CREATE USER pss_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE pss_backend TO pss_user;

# Exit
\q
```

Update your `.env`:
```bash
DATABASE_URL=postgresql://pss_user:your_password@localhost:5432/pss_backend
```

#### Option B: Neon Serverless (Recommended)

1. Sign up at [Neon](https://neon.tech)
2. Create a new project
3. Copy the connection string
4. Update `.env`:

```bash
DATABASE_URL=postgresql://username:password@aws-0-us-east-1.pooler.neon.tech/pss_db?sslmode=require
```

**⚠️ Important for Neon**: Use Session Mode pooler, not Transaction Mode!

### 6. Run Database Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

You should see:
```
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying users.0001_initial... OK
  Applying admin.0001_initial... OK
  ...
```

### 7. Create Superuser

```bash
python manage.py createsuperuser
```

Follow the prompts:
```
Email: admin@example.com
Password: (enter password)
Password (again): (confirm password)
First name: Admin
Last name: User
Role: superuser
```

### 8. Load Sample Data (Optional)

```bash
python manage.py loaddata fixtures/sample_data.json
```

### 9. Run Development Server

```bash
python manage.py runserver
```

You should see:
```
Django version 4.2.7, using settings 'config.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.
```

### 10. Verify Installation

Open your browser and visit:

- **API Root**: http://localhost:8000/api/
- **Admin Panel**: http://localhost:8000/admin/
- **Health Check**: http://localhost:8000/health/

## Testing the API

### Using cURL

**Login:**
```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "your_password"
  }'
```

Response:
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "first_name": "Admin",
    "last_name": "User",
    "role": "superuser"
  }
}
```

**Access Protected Endpoint:**
```bash
curl -X GET http://localhost:8000/api/users/me/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using Postman

1. Import the Postman collection (if available)
2. Set up environment variables:
   - `base_url`: http://localhost:8000
   - `access_token`: (will be set after login)
3. Test authentication flow
4. Explore other endpoints

## Project Structure

```
Pss-backendN/
├── apps/                      # Django applications
│   ├── admin_notes/
│   ├── authentication/
│   ├── dashboard/
│   ├── intake/
│   ├── journal/
│   └── users/
├── config/                   # Project configuration
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── docs/                     # Documentation
├── venv/                     # Virtual environment (not in Git)
├── .env                      # Environment variables (not in Git)
├── .env.example              # Environment template
├── manage.py                 # Django management script
├── requirements.txt          # Python dependencies
└── README.md                 # Project README
```

## Common Development Tasks

### Running Migrations

After modifying models:
```bash
python manage.py makemigrations
python manage.py migrate
```

### Creating a New App

```bash
python manage.py startapp app_name
```

Don't forget to:
1. Move to `apps/` directory
2. Add to `INSTALLED_APPS` in `settings.py`
3. Create URLs and add to root `urls.py`

### Django Shell

Access Django shell for testing:
```bash
python manage.py shell
```

Example:
```python
from apps.users.models import User

# Get all users
users = User.objects.all()
print(users)

# Create a user
user = User.objects.create_user(
    email='test@example.com',
    password='testpass123',
    first_name='Test',
    last_name='User',
    role='candidate'
)
```

### Database Shell

Access PostgreSQL directly:
```bash
python manage.py dbshell
```

### Clear Database

**⚠️ Warning: This deletes all data!**

```bash
python manage.py flush
```

### Run Tests

```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test apps.users

# Run with coverage
coverage run --source='.' manage.py test
coverage report
```

## Troubleshooting

### Issue: Database Connection Error

**Error:**
```
django.db.utils.OperationalError: could not connect to server
```

**Solutions:**
1. Check PostgreSQL is running:
   ```bash
   # macOS
   brew services list
   brew services start postgresql@16

   # Linux
   sudo systemctl status postgresql
   sudo systemctl start postgresql
   ```

2. Verify DATABASE_URL in `.env`
3. Check database exists:
   ```bash
   psql -U postgres -l
   ```

### Issue: Neon Database "Prepared transactions are disabled"

**Error:**
```
OperationalError: prepared transactions are disabled
```

**Solution:**
Add to your DATABASE_URL:
```bash
DATABASE_URL=postgresql://...?sslmode=require&options=-c%20jit=off
```

Or in `settings.py`:
```python
DATABASES = {
    'default': {
        ...
        'OPTIONS': {
            'options': '-c jit=off'
        },
    }
}
```

### Issue: Migrations Not Applying

**Solutions:**
1. Check for migration conflicts:
   ```bash
   python manage.py showmigrations
   ```

2. Fake migrations if needed (⚠️ use with caution):
   ```bash
   python manage.py migrate --fake app_name migration_name
   ```

3. Reset migrations (⚠️ development only):
   ```bash
   # Delete migration files (except __init__.py)
   # Drop database
   # Recreate and migrate
   ```

### Issue: CORS Errors

**Error:**
```
Access to fetch at 'http://localhost:8000/api/' from origin 'http://localhost:5173'
has been blocked by CORS policy
```

**Solutions:**
1. Add origin to `.env`:
   ```bash
   CORS_ALLOWED_ORIGINS=http://localhost:5173
   ```

2. Check `settings.py` has:
   ```python
   INSTALLED_APPS = [
       'corsheaders',
       ...
   ]

   MIDDLEWARE = [
       'corsheaders.middleware.CorsMiddleware',
       ...
   ]
   ```

### Issue: JWT Token Invalid

**Error:**
```
401 Unauthorized: Token is invalid or expired
```

**Solutions:**
1. Check token hasn't expired (15 min default)
2. Refresh the token:
   ```bash
   POST /api/auth/refresh/
   Body: { "refresh": "your_refresh_token" }
   ```
3. Login again if refresh token expired

### Issue: Permission Denied

**Error:**
```
403 Forbidden: You do not have permission to perform this action
```

**Solutions:**
1. Check user role matches endpoint requirements
2. Verify JWT token in header:
   ```
   Authorization: Bearer <token>
   ```
3. Check permission classes in view

### Issue: SECRET_KEY Warning

**Warning:**
```
?: (security.W009) Your SECRET_KEY has less than 50 characters
```

**Solution:**
Generate a new secret key:
```python
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())
```

Add to `.env`:
```bash
SECRET_KEY=new-secret-key-here
```

## Development Best Practices

### 1. Git Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and commit
git add .
git commit -m "Description of changes"

# Push to remote
git push origin feature/your-feature-name

# Create Pull Request on GitHub
```

### 2. Code Style

Follow PEP 8 guidelines:
```bash
# Install flake8
pip install flake8

# Check code
flake8 apps/

# Auto-format with black (planned)
pip install black
black apps/
```

### 3. Environment Management

- Never commit `.env`
- Update `.env.example` when adding new variables
- Use different `.env` files for dev/staging/prod

### 4. Database Management

- Always create migrations after model changes
- Test migrations on development database first
- Never modify migration files directly
- Keep migrations in version control

### 5. Testing

- Write tests for new features
- Run tests before committing
- Aim for 80% code coverage
- Test edge cases and error handling

## Next Steps

1. ✅ Development environment set up
2. 📖 Read [Architecture Overview](./Architecture.md)
3. 📋 Review [Handover Roadmap](./Handover-Roadmap.md)
4. 🔐 Check [Security & Compliance](./Security-Compliance.md)
5. 🐛 Pick an issue from [GitHub Issues](https://github.com/Clickatell4/Pss-backendN/issues)
6. 💻 Start coding!

## Useful Commands Reference

```bash
# Virtual Environment
source venv/bin/activate              # Activate (macOS/Linux)
venv\Scripts\activate                 # Activate (Windows)
deactivate                            # Deactivate

# Django Management
python manage.py runserver            # Start dev server
python manage.py makemigrations       # Create migrations
python manage.py migrate              # Apply migrations
python manage.py createsuperuser      # Create admin user
python manage.py shell                # Django shell
python manage.py test                 # Run tests
python manage.py collectstatic        # Collect static files

# Database
python manage.py dbshell              # Database shell
python manage.py flush                # Clear database
python manage.py dumpdata             # Export data
python manage.py loaddata             # Import data

# Dependencies
pip install -r requirements.txt       # Install dependencies
pip freeze > requirements.txt         # Update requirements
pip list                              # List installed packages
```

---

**Last Updated**: January 11, 2026
**Version**: 2.0

## Getting Help

- **Documentation Issues**: Create an issue on GitHub
- **Setup Problems**: Check this troubleshooting guide
- **Questions**: Ask in team Slack channel
- **Bugs**: Report on [GitHub Issues](https://github.com/Clickatell4/Pss-backendN/issues)
