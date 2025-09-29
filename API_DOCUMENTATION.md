# PSS Backend API Documentation

## Base URL
```
https://pss-backend-production-adc4.up.railway.app/
```

## Authentication
The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

---

## 🔐 Authentication Endpoints

### Register User
```http
POST /api/auth/register/
Content-Type: application/json

{
  "email": "student@capaciti.org.za",
  "password": "secure_password",
  "first_name": "John",
  "last_name": "Doe",
  "role": "candidate"
}
```

**Response (201):**
```json
{
  "user": {
    "id": 1,
    "email": "student@capaciti.org.za",
    "first_name": "John",
    "last_name": "Doe",
    "role": "candidate",
    "has_completed_intake": false
  },
  "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### Login
```http
POST /api/auth/login/
Content-Type: application/json

{
  "email": "student@capaciti.org.za",
  "password": "secure_password"
}
```

**Response (200):**
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": 1,
    "email": "student@capaciti.org.za",
    "first_name": "John",
    "last_name": "Doe",
    "role": "candidate",
    "has_completed_intake": false
  }
}
```

### Logout
```http
POST /api/auth/logout/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### Get Current User
```http
GET /api/auth/user/
Authorization: Bearer <access_token>
```

### Refresh Token
```http
POST /api/auth/token/refresh/
Content-Type: application/json

{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

---

## 👥 User Management

### Get User Profile
```http
GET /api/users/profile/
Authorization: Bearer <access_token>
```

### Update User Profile
```http
PUT /api/users/profile/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "first_name": "John",
  "last_name": "Doe",
  "date_of_birth": "1995-06-15",
  "contact_number": "+27123456789",
  "address": "123 Main St, Cape Town",
  "emergency_contact": "Jane Doe",
  "emergency_phone": "+27987654321",
  "diagnosis": "ADHD",
  "medications": "Ritalin 10mg daily",
  "allergies": "None known",
  "accommodations": "Extended time for exams",
  "assistive_technology": "Screen reader",
  "learning_style": "Visual learner",
  "support_needs": "Regular check-ins",
  "communication_preferences": "Email preferred"
}
```

---

## 📝 Intake Form

### Submit Intake Form
```http
POST /api/intake/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "personal_info": {
    "date_of_birth": "1995-06-15",
    "id_number": "9506150123456",
    "contact_number": "+27123456789",
    "address": "123 Main St, Cape Town"
  },
  "emergency_contact": {
    "name": "Jane Doe",
    "phone": "+27987654321"
  },
  "medical_info": {
    "diagnosis": "ADHD",
    "medications": "Ritalin 10mg daily",
    "allergies": "None known",
    "medical_notes": "Regular monitoring required",
    "doctor_name": "Dr. Smith",
    "doctor_phone": "+27111222333"
  },
  "accommodation_needs": {
    "accommodations": "Extended time for exams",
    "assistive_technology": "Screen reader",
    "learning_style": "Visual learner",
    "support_needs": "Regular check-ins",
    "communication_preferences": "Email preferred"
  }
}
```

### Get User's Intake Form
```http
GET /api/intake/
Authorization: Bearer <access_token>
```

---

## 📖 Journal Entries

### Create Journal Entry
```http
POST /api/journal/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "title": "Today's Reflection",
  "content": "Had a great day learning React. Feeling confident about the upcoming project.",
  "mood": "positive",
  "tags": ["learning", "react", "confidence"]
}
```

### Get All Journal Entries
```http
GET /api/journal/
Authorization: Bearer <access_token>
```

**Optional Query Parameters:**
- `?mood=positive` - Filter by mood
- `?date=2025-09-29` - Filter by date
- `?search=react` - Search in title/content

### Get Specific Journal Entry
```http
GET /api/journal/{id}/
Authorization: Bearer <access_token>
```

### Update Journal Entry
```http
PUT /api/journal/{id}/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "title": "Updated Title",
  "content": "Updated content",
  "mood": "neutral"
}
```

### Delete Journal Entry
```http
DELETE /api/journal/{id}/
Authorization: Bearer <access_token>
```

---

## 📊 Dashboard Data

### Get Dashboard Overview
```http
GET /api/dashboard/
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "user_stats": {
    "total_journal_entries": 15,
    "entries_this_week": 3,
    "entries_this_month": 12,
    "most_common_mood": "positive",
    "intake_completed": true
  },
  "recent_entries": [
    {
      "id": 1,
      "title": "Today's Reflection",
      "mood": "positive",
      "created_at": "2025-09-29T10:30:00Z"
    }
  ],
  "mood_distribution": {
    "positive": 8,
    "neutral": 5,
    "negative": 2
  }
}
```

---

## 📝 Admin Notes (Admin Only)

### Create Admin Note
```http
POST /api/admin-notes/
Authorization: Bearer <admin_access_token>
Content-Type: application/json

{
  "student_id": 1,
  "title": "Check-in Meeting",
  "content": "Student is progressing well. Discussed upcoming project deadlines.",
  "category": "check-in",
  "is_private": false
}
```

### Get Admin Notes for Student
```http
GET /api/admin-notes/?student_id=1
Authorization: Bearer <access_token>
```

---

## 🔍 Error Responses

### 400 Bad Request
```json
{
  "error": "Validation failed",
  "details": {
    "email": ["This field is required."],
    "password": ["Password must be at least 8 characters."]
  }
}
```

### 401 Unauthorized
```json
{
  "detail": "Given token not valid for any token type",
  "code": "token_not_valid",
  "messages": [
    {
      "token_class": "AccessToken",
      "token_type": "access",
      "message": "Token is invalid or expired"
    }
  ]
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

---

## 📱 Frontend Integration Examples

### React/JavaScript Example

```javascript
// API Client Setup
const API_BASE_URL = 'https://your-railway-app.up.railway.app';

class APIClient {
  constructor() {
    this.baseURL = API_BASE_URL;
    this.token = localStorage.getItem('access_token');
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    if (this.token) {
      config.headers.Authorization = `Bearer ${this.token}`;
    }

    const response = await fetch(url, config);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  // Authentication
  async login(email, password) {
    const response = await this.request('/api/auth/login/', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    this.token = response.access;
    localStorage.setItem('access_token', response.access);
    localStorage.setItem('refresh_token', response.refresh);

    return response;
  }

  async logout() {
    const refreshToken = localStorage.getItem('refresh_token');
    await this.request('/api/auth/logout/', {
      method: 'POST',
      body: JSON.stringify({ refresh: refreshToken }),
    });

    this.token = null;
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }

  // Journal Entries
  async getJournalEntries() {
    return this.request('/api/journal/');
  }

  async createJournalEntry(entry) {
    return this.request('/api/journal/', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
  }

  // Dashboard
  async getDashboard() {
    return this.request('/api/dashboard/');
  }

  // User Profile
  async getUserProfile() {
    return this.request('/api/users/profile/');
  }

  async updateUserProfile(profileData) {
    return this.request('/api/users/profile/', {
      method: 'PUT',
      body: JSON.stringify(profileData),
    });
  }
}

// Usage
const api = new APIClient();

// Login
try {
  const user = await api.login('student@capaciti.org.za', 'password');
  console.log('Logged in:', user);
} catch (error) {
  console.error('Login failed:', error);
}

// Create journal entry
try {
  const entry = await api.createJournalEntry({
    title: 'Learning Progress',
    content: 'Made great progress with React hooks today',
    mood: 'positive'
  });
  console.log('Entry created:', entry);
} catch (error) {
  console.error('Failed to create entry:', error);
}
```

---

## 🔧 Important Notes

1. **Email Validation**: All user emails must end with `@capaciti.org.za`

2. **Role-Based Access**:
   - `candidate` - Regular students
   - `admin` - Staff members with additional permissions

3. **CORS**: Frontend should be configured to handle CORS properly

4. **Token Refresh**: Implement automatic token refresh logic in your frontend

5. **Error Handling**: Always handle API errors gracefully in your frontend

6. **Rate Limiting**: Be mindful of API rate limits (if implemented)

---

## 🚀 Getting Started Checklist

- [ ] Set up API client with base URL
- [ ] Implement authentication flow (login/logout)
- [ ] Add token storage and refresh logic
- [ ] Create forms for user registration and login
- [ ] Build journal entry creation/editing interface
- [ ] Implement dashboard with user statistics
- [ ] Add error handling and loading states
- [ ] Test all endpoints with your Railway deployment URL

---

**Questions?** Once the 502 errors are resolved, you can test these endpoints directly!