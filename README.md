# PSS Backend - Personal Support System

Django REST API backend for the Personal Support System (PSS) application designed for CAPACITI students with disabilities.

## 🏗️ Project Structure

```
Pss-backendN/
├── manage.py                    # Django management script
├── requirements.txt             # Python dependencies
├── runtime.txt                  # Python version for deployment
├── Procfile                     # Deployment configuration
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore rules
├── README.md                    # This file
├── API_DOCUMENTATION.md         # Comprehensive API docs
├── logs/                        # Application logs
├── .venv/                       # Virtual environment (not in git)
├── pss_backend/                 # Django project configuration
│   ├── __init__.py
│   ├── settings.py              # Django settings
│   ├── urls.py                  # Main URL configuration
│   ├── wsgi.py                  # WSGI application
│   └── asgi.py                  # ASGI application
└── apps/                        # Django applications
    ├── __init__.py
    ├── authentication/          # JWT authentication
    ├── users/                   # User management & profiles
    ├── intake/                  # Intake form processing
    ├── journal/                 # Journal entries
    ├── admin_notes/             # Administrative notes
    └── dashboard/               # Dashboard statistics
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 12+
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Pss-backendN
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv .venv

   # On Windows
   .venv\Scripts\activate

   # On macOS/Linux
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment setup**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Database setup**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   python manage.py createsuperuser
   ```

6. **Run development server**
   ```bash
   python manage.py runserver
   ```

## 🔧 Environment Variables

Create a `.env` file based on `.env.example`:

### Required Variables
```env
SECRET_KEY=your-secret-key-here
DB_NAME=your_database_name
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_HOST=localhost
DB_PORT=5432
```

### Optional Variables (with defaults)
```env
DEBUG=False
ALLOWED_HOSTS=127.0.0.1,localhost
CORS_ALLOWED_ORIGINS=http://localhost:5173
SECURE_SSL_REDIRECT=False
CSRF_COOKIE_SECURE=False
SESSION_COOKIE_SECURE=False
```

## 📊 Features

### Core Functionality
- **JWT Authentication** - Secure token-based authentication
- **User Management** - Role-based access (Admin/Candidate)
- **Intake System** - Comprehensive intake form processing
- **Journal System** - Daily journal entries with mood/energy tracking
- **Admin Notes** - Administrative notes for candidate tracking
- **Dashboard Analytics** - Real-time statistics and insights

### Security Features
- Email domain validation (@capaciti.org.za only)
- Role-based permissions
- CORS configuration
- Security headers (HSTS, XSS protection)
- Environment-based configuration
- Token blacklisting on logout

### API Features
- RESTful API design
- Comprehensive error handling
- Pagination support
- Filtering and search
- Rate limiting
- Comprehensive documentation

## 🔐 User Roles

### Candidates
- Manage their own profile and intake information
- Create and manage journal entries
- View their own admin notes
- Access personal dashboard statistics

### Admins
- View and manage all candidate data
- Create and manage admin notes
- Access comprehensive dashboard analytics
- User management capabilities

## 📡 API Endpoints

Base URL: `http://localhost:8000/api/`

### Authentication
- `POST /auth/login/` - User login
- `POST /auth/logout/` - User logout
- `POST /auth/refresh/` - Refresh token
- `GET /auth/me/` - Current user details

### Users
- `GET /users/` - List users (admin only)
- `GET /users/candidates/` - List candidates (admin only)
- `GET /users/{id}/profile/` - User profile

### Intake
- `POST /intake/` - Submit intake form
- `GET /intake/{user_id}/` - Get intake details

### Journal
- `GET /journal/` - List journal entries
- `POST /journal/` - Create journal entry
- `GET /journal/stats/` - Journal statistics

### Admin Notes
- `GET /admin-notes/` - List admin notes
- `POST /admin-notes/` - Create admin note
- `GET /admin-notes/candidate/{id}/` - Candidate notes

### Dashboard
- `GET /dashboard/admin-stats/` - Admin dashboard
- `GET /dashboard/candidate-stats/` - Candidate dashboard

For detailed API documentation, see [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

## 🧪 Testing

```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test apps.users

# Run with coverage
coverage run manage.py test
coverage report
```

## 📦 Deployment

### Production Checklist
- [ ] Set `DEBUG=False`
- [ ] Configure production database
- [ ] Set up SSL/TLS certificates
- [ ] Configure static file serving
- [ ] Set up logging
- [ ] Configure CORS for production domain
- [ ] Set security environment variables

### Environment Variables for Production
```env
DEBUG=False
ALLOWED_HOSTS=your-domain.com
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com
SECURE_SSL_REDIRECT=True
CSRF_COOKIE_SECURE=True
SESSION_COOKIE_SECURE=True
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=True
SECURE_HSTS_PRELOAD=True
```

### Deployment Commands
```bash
# Collect static files
python manage.py collectstatic --noinput

# Run migrations
python manage.py migrate

# Create superuser (if needed)
python manage.py createsuperuser
```

## 🛠️ Development

### Adding New Apps
```bash
python manage.py startapp app_name apps/app_name
```

### Database Migrations
```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Show migration status
python manage.py showmigrations
```

### Code Quality
```bash
# Format code with black
black .

# Lint with flake8
flake8 .

# Type checking with mypy
mypy .
```

## 📋 Requirements

### Core Dependencies
- Django 4.2.7
- Django REST Framework 3.14.0
- django-cors-headers 4.3.1
- djangorestframework-simplejwt 5.3.0
- psycopg2-binary 2.9.7
- python-decouple 3.8
- django-filter 23.3
- pillow 10.0.1

### Development Dependencies
- gunicorn (production server)
- python-dotenv (environment management)

## 🐛 Troubleshooting

### Common Issues

1. **ModuleNotFoundError: No module named 'django'**
   - Ensure virtual environment is activated
   - Run `pip install -r requirements.txt`

2. **Database connection errors**
   - Check database credentials in `.env`
   - Ensure PostgreSQL is running
   - Verify database exists

3. **CORS errors**
   - Check `CORS_ALLOWED_ORIGINS` in settings
   - Ensure frontend domain is included

4. **Permission denied errors**
   - Check user roles and permissions
   - Verify JWT token is valid

## 📞 Support

For issues and questions:
1. Check the [API Documentation](API_DOCUMENTATION.md)
2. Review the troubleshooting section above
3. Check Django logs in `logs/` directory
4. Contact the development team

## 📄 License

This project is proprietary software developed for CAPACITI.

---

**Note**: This README assumes you have basic knowledge of Django and REST APIs. For detailed API usage, refer to the comprehensive [API Documentation](API_DOCUMENTATION.md).