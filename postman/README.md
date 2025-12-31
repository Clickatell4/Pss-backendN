# PSS Backend Postman Collection

Complete Postman collection for testing the PSS Backend API.

## What's Included

- **PSS_Backend_Testing.postman_collection.json** - Complete collection with 70+ endpoints
- **test_data.json** - Sample test data for all endpoint types
- This README with setup instructions

## Quick Start

### 1. Import Collection

1. Open Postman
2. Click **Import** button
3. Select `PSS_Backend_Testing.postman_collection.json`
4. Collection will appear in your Collections sidebar

### 2. Create Environment

1. Click **Environments** (left sidebar)
2. Click **+** to create new environment
3. Name it: `PSS Testing`
4. Add this variable:
   - **Variable**: `base_url`
   - **Initial Value**: `https://pss-backend-testing.onrender.com`
   - **Current Value**: `https://pss-backend-testing.onrender.com`
5. Click **Save**
6. Select `PSS Testing` environment from dropdown (top right)

### 3. Test Connection

1. Open collection → **✅ Health Check** → **API Health Check**
2. Click **Send**
3. You should see:
   ```json
   {
     "status": "healthy",
     "message": "PSS Backend API is running"
   }
   ```

### 4. Login

1. Open **🔐 Authentication** → **Login (Candidate)**
2. Update the request body with valid credentials (see test_data.json)
3. Click **Send**
4. **Access token automatically saved** to environment variables!

### 5. Make Authenticated Requests

All authenticated endpoints will automatically use the saved `access_token`.

Example:
1. Open **👥 User Management** → **Get Current User**
2. Click **Send** (no manual token needed!)
3. See your user profile

## Collection Structure

### 🔐 Authentication (5 requests)
- Login (Candidate)
- Login (Admin)
- Get Current User
- Register New Candidate
- Logout

### 🔑 Password Management (4 requests)
- Request Password Reset
- Validate Reset Token
- Confirm Password Reset
- Change Password (Authenticated)

### 🔒 Two-Factor Authentication (5 requests)
- Setup 2FA
- Verify 2FA Setup
- Verify 2FA Code (Login)
- Disable 2FA
- Regenerate Backup Codes

### 📱 Session Management (5 requests)
- List My Sessions
- Terminate All Sessions
- Terminate All Except Current
- Admin: List All Sessions
- Admin: Force Logout User

### 👥 User Management (5 requests)
- List All Users
- Get User Details
- Update User Profile
- Get User Profile
- List Candidates

### 📝 Intake Form (2 requests)
- Submit Intake Form
- Get User Intake Details

### 📖 Journal (6 requests)
- List Journal Entries
- Create Journal Entry
- Get Journal Entry
- Update Journal Entry
- Delete Journal Entry
- Get Journal Statistics

### 📋 Admin Notes (4 requests)
- List Admin Notes
- Create Admin Note
- Get Admin Note
- Get Notes for Candidate

### 📊 Dashboard (2 requests)
- Admin Dashboard Stats
- Candidate Dashboard Stats

### 🔐 POPIA/GDPR Compliance (6 requests)
- Get Privacy Policy
- List My Consents
- Grant Consent
- Withdraw Consent
- Export My Data
- Request Account Deletion

### ✅ Health Check (2 requests)
- Root Health Check
- API Health Check

## Features

### Automatic Token Management

The collection includes pre-request and test scripts that automatically:
- Save access token from login response
- Save refresh token
- Save user ID and email
- Add Authorization header to all authenticated requests

**No manual copy-paste needed!**

### Built-in Tests

Many requests include automated tests that check:
- Response status codes
- Response structure
- Data validation

Example from Login:
```javascript
pm.test('Login successful', () => {
    pm.expect(response).to.have.property('access');
    pm.expect(response).to.have.property('user');
});
```

### Environment Variables

The collection uses these environment variables:
- `base_url` - Base URL for the API
- `access_token` - JWT access token (auto-updated)
- `refresh_token` - JWT refresh token (auto-updated)
- `user_id` - Current user ID (auto-updated)
- `user_email` - Current user email (auto-updated)

## Test Data

See `test_data.json` for complete sample data including:

- Test user credentials for each role
- Sample intake form data
- Sample journal entries (3 examples with different moods)
- Sample admin notes (4 types)
- Test scenarios for complex flows
- Common errors and solutions

## Common Workflows

### Complete User Journey - Candidate

1. **Register**
   - Authentication → Register New Candidate

2. **Login**
   - Authentication → Login (Candidate)
   - Token automatically saved

3. **Complete Intake**
   - Intake Form → Submit Intake Form
   - Use data from test_data.json

4. **Create Journal Entry**
   - Journal → Create Journal Entry
   - Use sample from test_data.json

5. **View Dashboard**
   - Dashboard → Candidate Dashboard Stats

6. **Logout**
   - Authentication → Logout

### Admin Workflow

1. **Login as Admin**
   - Authentication → Login (Admin)

2. **View All Candidates**
   - User Management → List Candidates

3. **Create Admin Note**
   - Admin Notes → Create Admin Note
   - Use sample from test_data.json

4. **View Admin Dashboard**
   - Dashboard → Admin Dashboard Stats

5. **Manage Sessions**
   - Session Management → Admin: List All Sessions
   - Session Management → Admin: Force Logout User

### Testing 2FA

1. **Login without 2FA**
   - Authentication → Login (Candidate)

2. **Setup 2FA**
   - Two-Factor Authentication → Setup 2FA
   - Scan QR code with Google Authenticator

3. **Verify Setup**
   - Two-Factor Authentication → Verify 2FA Setup
   - Enter code from authenticator app
   - **Save backup codes!**

4. **Logout**
   - Authentication → Logout

5. **Login with 2FA**
   - Authentication → Login (Candidate)
   - Will return `requires_2fa: true`

6. **Complete 2FA**
   - Two-Factor Authentication → Verify 2FA Code (Login)
   - Enter current TOTP code

## Troubleshooting

### 401 Unauthorized

**Problem**: Token expired or invalid

**Solution**:
1. Go to Authentication → Login (Candidate/Admin)
2. Send request to get fresh token
3. Token automatically saves - try your request again

### 403 Forbidden

**Problem**: Insufficient permissions

**Solution**:
- Use admin account for admin-only endpoints
- Check endpoint documentation for required role

### Variables Not Saving

**Problem**: Environment not selected

**Solution**:
1. Check top-right dropdown
2. Ensure `PSS Testing` environment is selected
3. Try login again

### Base URL Not Found

**Problem**: Environment variable not set

**Solution**:
1. Go to Environments
2. Select `PSS Testing`
3. Verify `base_url` is set to `https://pss-backend-testing.onrender.com`

## Running Collection Tests

### Option 1: Collection Runner (UI)

1. Click **Collections** → **PSS Backend - Testing Environment**
2. Click **Run** button
3. Select requests to run
4. Configure iterations, delay
5. Click **Run PSS Backend - Testing Environment**
6. View test results

### Option 2: Newman (Command Line)

```bash
# Install Newman
npm install -g newman

# Run collection
newman run PSS_Backend_Testing.postman_collection.json \
  --environment pss-testing-environment.json

# With detailed results
newman run PSS_Backend_Testing.postman_collection.json \
  --environment pss-testing-environment.json \
  --reporters cli,html \
  --reporter-html-export results.html
```

## Additional Resources

- **API Documentation**: `/docs/confluence/api-reference.md`
- **Test Scenarios**: `/docs/confluence/test-scenarios.md`
- **Security Testing**: `/docs/confluence/security-testing.md`
- **Troubleshooting Guide**: `/docs/confluence/troubleshooting.md`

## Support

For issues or questions:
1. Check the troubleshooting section above
2. See `/docs/confluence/troubleshooting.md`
3. Contact the development team

---

**Last Updated**: 2025-12-31
**Version**: 1.0
**Maintained By**: PSS Backend Team
