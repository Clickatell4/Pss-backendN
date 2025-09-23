# PSS Backend API Documentation

## Overview
Django REST API backend for the Personal Support System (PSS) application designed for CAPACITI students with disabilities.

## Project Structure
```
Pss-backendN/
├── manage.py                    # Django management script
├── apps/                        # Django applications
│   ├── authentication/          # JWT authentication
│   ├── users/                   # User management & profiles
│   ├── intake/                  # Intake form processing
│   ├── journal/                 # Journal entries
│   ├── admin_notes/             # Administrative notes
│   └── dashboard/               # Dashboard statistics
└── pss_backend/                 # Django project configuration
    ├── settings.py              # Django settings
    ├── urls.py                  # Main URL configuration
    └── wsgi.py                  # WSGI application
```

## Base URL
- Development: `http://localhost:8000/api/`
- Production: `https://your-domain.com/api/`

## Authentication
All API endpoints (except login) require JWT authentication.

### Headers
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

## API Endpoints

### Authentication Endpoints

#### Login
- **POST** `/auth/login/`
- **Description**: Authenticate user and receive JWT tokens
- **Body**:
```json
{
  "email": "user@capaciti.org.za",
  "password": "password123"
}
```
- **Response**:
```json
{
  "access": "jwt_access_token",
  "refresh": "jwt_refresh_token",
  "user": {
    "id": 1,
    "email": "user@capaciti.org.za",
    "first_name": "John",
    "last_name": "Doe",
    "role": "candidate",
    "has_completed_intake": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
    "profile": { ... }
  }
}
```

#### Logout
- **POST** `/auth/logout/`
- **Description**: Blacklist refresh token
- **Body**:
```json
{
  "refresh": "jwt_refresh_token"
}
```

#### Refresh Token
- **POST** `/auth/refresh/`
- **Description**: Get new access token using refresh token
- **Body**:
```json
{
  "refresh": "jwt_refresh_token"
}
```

#### Current User
- **GET** `/auth/me/`
- **Description**: Get current authenticated user details

### User Management Endpoints

#### List/Create Users
- **GET** `/users/` - List all users (admin only)
- **POST** `/users/` - Create new user (admin only)

#### User Detail
- **GET** `/users/{id}/` - Get user details
- **PUT** `/users/{id}/` - Update user
- **DELETE** `/users/{id}/` - Delete user (admin only)

#### User Profile
- **GET** `/users/{id}/profile/` - Get user profile
- **PUT** `/users/{id}/profile/` - Update user profile

#### Candidates List
- **GET** `/users/candidates/` - List all candidates (admin only)
- **Response**:
```json
{
  "count": 25,
  "results": [
    {
      "id": 1,
      "first_name": "John",
      "last_name": "Doe",
      "email": "john.doe@capaciti.org.za",
      "has_completed_intake": true,
      "profile": {
        "diagnosis": "Visual impairment",
        "accommodations": "Screen reader support"
      },
      "journal_stats": {
        "total_entries": 5,
        "last_entry_date": "2024-01-15",
        "recent_barriers": 0,
        "avg_energy_level": 7.2
      },
      "admin_notes_count": 2
    }
  ]
}
```

### Intake Endpoints

#### Submit Intake
- **POST** `/intake/`
- **Description**: Submit or update intake information
- **Body**:
```json
{
  "intake_data": {
    "date_of_birth": "1990-01-01",
    "id_number": "9001010000000",
    "contact_number": "+27123456789",
    "address": "123 Main St, Cape Town",
    "emergency_contact": "Jane Doe",
    "emergency_phone": "+27987654321",
    "diagnosis": "Visual impairment",
    "medications": "None",
    "allergies": "None",
    "medical_notes": "Requires screen reader",
    "doctor_name": "Dr. Smith",
    "doctor_phone": "+27111222333",
    "accommodations": "Screen reader, extra time for tests",
    "assistive_technology": "JAWS screen reader",
    "learning_style": "Auditory",
    "support_needs": "Technical support for assistive technology",
    "communication_preferences": "Email and verbal communication"
  }
}
```

#### Get Intake Details
- **GET** `/intake/{user_id}/`
- **Description**: Get intake details for a specific user

### Journal Endpoints

#### List/Create Journal Entries
- **GET** `/journal/` - List user's journal entries
- **POST** `/journal/` - Create new journal entry
- **Body**:
```json
{
  "date": "2024-01-15",
  "mood": "good",
  "energy_level": 7,
  "activities": "Attended classes, completed assignments",
  "challenges": "Had difficulty with online platform",
  "achievements": "Completed Python module",
  "notes": "Feeling confident about progress",
  "barriers_faced": "Technical issues with screen reader",
  "barrier_count": 1
}
```

#### Journal Entry Detail
- **GET** `/journal/{id}/` - Get specific journal entry
- **PUT** `/journal/{id}/` - Update journal entry
- **DELETE** `/journal/{id}/` - Delete journal entry

#### Journal Statistics
- **GET** `/journal/stats/`
- **Description**: Get journal statistics for current user

### Admin Notes Endpoints

#### List/Create Admin Notes
- **GET** `/admin-notes/` - List admin notes (filtered by permissions)
- **POST** `/admin-notes/` - Create new admin note (admin only)
- **Body**:
```json
{
  "candidate": 1,
  "category": "progress",
  "title": "Weekly Progress Update",
  "content": "Student is making good progress with Python fundamentals",
  "is_important": false
}
```

#### Admin Note Detail
- **GET** `/admin-notes/{id}/` - Get specific admin note
- **PUT** `/admin-notes/{id}/` - Update admin note
- **DELETE** `/admin-notes/{id}/` - Delete admin note

#### Candidate Notes
- **GET** `/admin-notes/candidate/{candidate_id}/`
- **Description**: Get all admin notes for a specific candidate

### Dashboard Endpoints

#### Admin Dashboard Stats
- **GET** `/dashboard/admin-stats/` (admin only)
- **Response**:
```json
{
  "total_candidates": 25,
  "active_candidates": 20,
  "pending_intake": 5,
  "recent_barriers": 12,
  "recent_entries": 45,
  "total_admin_notes": 78,
  "recent_admin_notes": 15
}
```

#### Candidate Dashboard
- **GET** `/dashboard/candidate-stats/` (candidates only)
- **Response**:
```json
{
  "total_entries": 15,
  "last_entry_date": "2024-01-15",
  "avg_energy_level": 7.2,
  "recent_barriers": 3,
  "admin_notes_count": 5,
  "mood_distribution": [
    {"mood": "excellent", "count": 3},
    {"mood": "good", "count": 8},
    {"mood": "okay", "count": 4}
  ],
  "has_completed_intake": true
}
```

## Data Models

### User Model
- `id`: Integer (auto)
- `email`: Email (unique, must end with @capaciti.org.za)
- `first_name`: String
- `last_name`: String
- `role`: Choice ('candidate', 'admin')
- `has_completed_intake`: Boolean
- `is_active`: Boolean
- `is_staff`: Boolean
- `date_joined`: DateTime
- `created_at`: DateTime
- `updated_at`: DateTime

### UserProfile Model
- Personal Information: date_of_birth, id_number, contact_number, address
- Emergency Contact: emergency_contact, emergency_phone
- Medical Information: diagnosis, medications, allergies, medical_notes, doctor_name, doctor_phone
- Accommodations: accommodations, assistive_technology, learning_style, support_needs, communication_preferences

### JournalEntry Model
- `user`: ForeignKey to User
- `date`: Date (unique per user per date)
- `mood`: Choice (excellent, good, okay, difficult, very_difficult)
- `energy_level`: Integer (1-10)
- `activities`: Text
- `challenges`: Text
- `achievements`: Text
- `notes`: Text
- `barriers_faced`: Text
- `barrier_count`: Integer

### AdminNote Model
- `candidate`: ForeignKey to User
- `admin`: ForeignKey to User
- `category`: Choice (progress, concern, achievement, medical, accommodation, general)
- `title`: String
- `content`: Text
- `is_important`: Boolean

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Error message",
  "errors": {
    "field_name": ["Field-specific error message"]
  }
}
```

### 401 Unauthorized
```json
{
  "detail": "Authentication credentials were not provided."
}
```

### 403 Forbidden
```json
{
  "detail": "You do not have permission to perform this action."
}
```

### 404 Not Found
```json
{
  "detail": "Not found."
}
```

## Permissions

### Role-Based Access Control
- **Candidates**: Can only access their own data
- **Admins**: Can access all candidate data and perform administrative functions

### Endpoint Permissions
- Authentication endpoints: Public (except logout, me)
- User management: Admin only (except own profile)
- Intake: Own data only
- Journal: Own data only
- Admin notes: Admin can create/read all, candidates can read their own
- Dashboard: Role-specific stats

## Environment Variables

See `.env.example` for required environment variables including:
- Database configuration
- Security settings
- CORS settings
- Debug mode settings