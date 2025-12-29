# Password Reset Architecture & Flow Diagrams

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND                                │
│  (React/Vue.js or similar)                                      │
│                                                                 │
│  ├─ Password Reset Page                                        │
│  │  └─ Email input → POST /password-reset/request/             │
│  │                                                              │
│  ├─ Reset Link Handler                                         │
│  │  ├─ Extract token from URL                                  │
│  │  └─ POST /password-reset/validate-token/                    │
│  │                                                              │
│  ├─ Reset Form Page                                            │
│  │  ├─ New password input                                      │
│  │  └─ POST /password-reset/confirm/                           │
│  │                                                              │
│  └─ Account Settings                                           │
│     └─ Old password + New password → POST /password-change/    │
│                                                                 │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                   HTTPS (Secure Communication)
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│                        DJANGO BACKEND                           │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐   │
│  │              Authentication Endpoints                  │   │
│  │                                                        │   │
│  │  • PasswordResetRequestView       (POST)             │   │
│  │    - Rate limit: 3/hour per IP                      │   │
│  │    - Email enumeration prevention                  │   │
│  │    - Token generation                             │   │
│  │    - Email sending                                │   │
│  │                                                        │   │
│  │  • PasswordResetValidateTokenView (POST)             │   │
│  │    - Token validation (without consuming)          │   │
│  │    - Used for frontend pre-validation              │   │
│  │                                                        │   │
│  │  • PasswordResetConfirmView       (POST)             │   │
│  │    - Rate limit: 5/15min per IP                   │   │
│  │    - Token verification                           │   │
│  │    - Password validation                          │   │
│  │    - Session invalidation                         │   │
│  │    - Token marking as used                        │   │
│  │                                                        │   │
│  │  • PasswordChangeView             (POST)             │   │
│  │    - Authentication required                      │   │
│  │    - Rate limit: 5/15min per IP                   │   │
│  │    - Old password verification                    │   │
│  │    - Password history check                       │   │
│  │    - Session invalidation                         │   │
│  │                                                        │   │
│  └────────────────────────────────────────────────────────┘   │
│                              │                                │
│              ┌───────────────┼────────────────┐               │
│              │               │                │               │
│  ┌──────────▼─┐  ┌─────────▼──┐  ┌─────────▼──┐             │
│  │  Database  │  │  Throttling│  │   Logging  │             │
│  │            │  │            │  │            │             │
│  │ • User     │  │ • Auth     │  │ • Security │             │
│  │ • Password │  │ • Register │  │   Logs     │             │
│  │   Reset    │  │ • Password │  │            │             │
│  │   Token    │  │   Reset    │  │ Audit Trail│             │
│  │ • Password │  │ • Password │  │            │             │
│  │   History  │  │   Change   │  │ • IP Addr  │             │
│  │            │  │            │  │ • Timestamp│             │
│  │            │  │            │  │ • User ID  │             │
│  │            │  │            │  │ • Event    │             │
│  └────────────┘  └────────────┘  └────────────┘             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │              Email Service                              │ │
│  │                                                          │ │
│  │  • send_password_reset_email()                         │ │
│  │    - HTML + Text format                                │ │
│  │    - Secure token link                                │ │
│  │    - Clear instructions                               │ │
│  │    - Expiry information                               │ │
│  │    - Security notice                                  │ │
│  │                                                          │ │
│  │  • send_password_change_confirmation_email()          │ │
│  │    - Success notification                             │ │
│  │    - Session invalidation notice                      │ │
│  │    - Security warning                                 │ │
│  │    - Support contact info                             │ │
│  │                                                          │ │
│  └──────────────────────────────────────────────────────────┘ │
│                              │                                │
└──────────────────────────────┼────────────────────────────────┘
                               │
                    SMTP/Email Backend
                               │
┌──────────────────────────────▼────────────────────────────────┐
│                      EMAIL PROVIDER                           │
│                                                                 │
│  • Gmail, SendGrid, Mailgun, etc.                            │
│  • Sends formatted emails to user                            │
│  • HTML templates rendered                                    │
│  • Attachments (if needed)                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Password Reset Flow (Diagram)

```
User                    Frontend               Backend              Database            Email
 │                         │                      │                    │                 │
 ├─ Visits Reset Page ──→  │                      │                    │                 │
 │                         │                      │                    │                 │
 ├─ Enters Email ────────→ │                      │                    │                 │
 │                         ├─ POST /password-reset/request/             │                 │
 │                         │──────────────────→  │                    │                 │
 │                         │                      ├─ Find User ────→  │                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Generate Token ─┐                  │
 │                         │                      │                   │                 │
 │                         │                      ├─ Hash Token ◄─┘                   │
 │                         │                      │                                     │
 │                         │                      ├─ Save to DB ────→│                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Return Success ←────────────────── │
 │                         │◄─────────────────────┤                    │                 │
 │                         │                      ├─ Send Email ──────────────────────→│
 │                         │                      │                    │                 │
 ├ Receives Email ◄────────────────────────────────────────────────────────────────────┤
 │                         │                      │                    │                 │
 ├─ Clicks Reset Link ──→  │                      │                    │                 │
 │                         │ (Extracts token from URL)               │                 │
 │                         │                      │                    │                 │
 │                         ├─ POST /password-reset/validate-token/     │                 │
 │                         │──────────────────→  │                    │                 │
 │                         │                      ├─ Hash Token ◄─┐                   │
 │                         │                      │                 ├─ Query DB ────→│
 │                         │                      │                  ◄────────────┘   │
 │                         │                      ├─ Check Expiry                      │
 │                         │                      │                                     │
 │                         │◄─────────────────────┤ Return {valid: true, email}        │
 │                         │                      │                                     │
 ├─ Shows Password Form ◄──┤                      │                    │                 │
 │                         │                      │                    │                 │
 ├─ Enters New Password ──→ │                      │                    │                 │
 │                         ├─ POST /password-reset/confirm/            │                 │
 │                         │──────────────────→  │                    │                 │
 │                         │                      ├─ Verify Token ──→ │                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Validate Password               │
 │                         │                      ├─ Check History ───→│                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Update Password ──→│                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Mark Token Used ──→│                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Invalidate Sessions              │
 │                         │                      │                    │                 │
 │                         │◄─────────────────────┤ Return {success}                   │
 │                         │                      │                                     │
 │                         │                      ├─ Send Confirmation Email ────────→│
 │                         │                      │                    │                 │
 ├ Redirect to Login ◄─────┤                      │                    │                 │
 │                         │                      │                    │                 │
 ├─ Logs in ─────────────→ │                      │                    │                 │
 │                         ├─ POST /auth/login/   │                    │                 │
 │                         │──────────────────→  │                    │                 │
 │                         │                      ├─ Authenticate ────→│                 │
 │                         │◄─────────────────────┤ Return Tokens                      │
 │                         │                      │                    │                 │
 ├─ Access Granted ◄───────┤                      │                    │                 │
```

---

## Password Change Flow (Authenticated User)

```
User                    Frontend               Backend              Database            Email
 │                         │                      │                    │                 │
 ├─ Visits Account ──────→  │                      │                    │                 │
 │   Settings                │                      │                    │                 │
 │                         │                      │                    │                 │
 ├─ Clicks "Change ──────→  │                      │                    │                 │
 │   Password"              │                      │                    │                 │
 │                         │                      │                    │                 │
 ├─ Enters Passwords ────→  │                      │                    │                 │
 │ (Old + New)              │                      │                    │                 │
 │                         ├─ POST /password-change/ (with Auth Token)                 │
 │                         │──────────────────→  │                    │                 │
 │                         │                      ├─ Verify Auth ────→ │                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Check Old Password              │
 │                         │                      │                                     │
 │                         │                      ├─ Validate New Password             │
 │                         │                      │                                     │
 │                         │                      ├─ Check History ───→│                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Update Password ──→│                 │
 │                         │                      │                    │                 │
 │                         │                      ├─ Store in History ──→│               │
 │                         │                      │                    │                 │
 │                         │                      ├─ Invalidate All Sessions           │
 │                         │                      │                    │                 │
 │                         │◄─────────────────────┤ Return {success}                   │
 │                         │                      │                                     │
 │                         │                      ├─ Send Confirmation Email ────────→│
 │                         │                      │                    │                 │
 ├ Shows Success ◄─────────┤                      │                    │                 │
 │ Message                  │                      │                    │                 │
 │ (May need to login       │                      │                    │                 │
 │  on other devices)       │                      │                    │                 │
 │                         │                      │                    │                 │
 ├ Receives Confirmation ◄──────────────────────────────────────────────────────────────┤
 │ Email                    │                      │                    │                 │
```

---

## Security Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: Input Validation                                     │
│  ├─ Email format validation                                    │
│  ├─ Password length validation (min 8 chars)                   │
│  ├─ CAPACITI domain check                                      │
│  └─ Text sanitization                                          │
│                                                                 │
│  Layer 2: Rate Limiting                                        │
│  ├─ Reset requests: 3/hour per IP                             │
│  ├─ Reset confirm: 5/15min per IP                             │
│  ├─ Password change: 5/15min per IP                           │
│  └─ Prevents brute force attacks                              │
│                                                                 │
│  Layer 3: Token Security                                       │
│  ├─ Cryptographically secure generation (256-bit)             │
│  ├─ SHA-256 hashing before storage                            │
│  ├─ 1-hour expiration (auto-invalidates)                      │
│  ├─ Single-use enforcement                                     │
│  └─ Audit trail (IP, user agent)                              │
│                                                                 │
│  Layer 4: Password Validation                                  │
│  ├─ Old password required for change                          │
│  ├─ Django validators (common passwords, etc.)               │
│  ├─ Cannot reuse same password                                │
│  ├─ Cannot reuse last 5 passwords                             │
│  └─ User info similarity check                                │
│                                                                 │
│  Layer 5: Email Security                                       │
│  ├─ No email enumeration (same response for all)             │
│  ├─ Secure token link in URL                                  │
│  ├─ HTML + Text formats                                       │
│  ├─ Clear security notices                                    │
│  └─ Professional templates                                    │
│                                                                 │
│  Layer 6: Session Management                                   │
│  ├─ All sessions invalidated after reset                      │
│  ├─ All sessions invalidated after change                     │
│  ├─ JWT token blacklist mechanism                             │
│  └─ Forces re-authentication                                  │
│                                                                 │
│  Layer 7: Logging & Monitoring                                │
│  ├─ All operations logged                                      │
│  ├─ Timestamp & IP tracking                                    │
│  ├─ Success/failure status                                     │
│  ├─ User identification (email)                                │
│  └─ Audit trail for compliance                                │
│                                                                 │
│  Layer 8: Database Security                                    │
│  ├─ Passwords hashed (Django PBKDF2)                          │
│  ├─ Tokens hashed (SHA-256)                                   │
│  ├─ No plaintext storage                                       │
│  └─ Encrypted sensitive fields                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Token Lifecycle

```
┌──────────────────────────────────────────────────────┐
│              TOKEN LIFECYCLE                         │
├──────────────────────────────────────────────────────┤
│                                                      │
│  1. GENERATION                                      │
│     ├─ User requests password reset                 │
│     ├─ System generates random token (256-bit)     │
│     ├─ Token hashed with SHA-256                    │
│     ├─ Hash stored in database                      │
│     └─ Plain token sent to user via email          │
│                                                      │
│  2. VALIDATION (Optional)                          │
│     ├─ User clicks link or enters token            │
│     ├─ Frontend validates token (optional step)    │
│     ├─ System checks:                              │
│     │  ├─ Token exists (hash lookup)               │
│     │  ├─ Not expired (< 1 hour old)               │
│     │  ├─ Not yet used (used=false)                │
│     │  └─ User is active                           │
│     └─ Returns validation result                    │
│                                                      │
│  3. CONFIRMATION                                    │
│     ├─ User submits new password with token        │
│     ├─ System verifies token again                 │
│     ├─ Validates new password                      │
│     ├─ Updates user password                        │
│     ├─ Marks token as used (used=true)            │
│     ├─ Records timestamp (used_at)                 │
│     └─ Invalidates all sessions                     │
│                                                      │
│  4. EXPIRATION                                      │
│     ├─ After 1 hour, token is expired             │
│     ├─ Subsequent validation attempts fail        │
│     ├─ User must request new token                 │
│     └─ Expired tokens kept for audit trail        │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## Error Handling Flow

```
User Action              │ Validation Check           │ Response
─────────────────────────┼────────────────────────────┼──────────────────────
Missing email            │ Email field empty?         │ 400: Email required
Invalid email format     │ Valid email format?        │ 400: Invalid email
Wrong domain             │ @capaciti.org.za?          │ 400: Invalid domain
Rate limit exceeded      │ <3 per hour?               │ 429: Try again later
─────────────────────────┼────────────────────────────┼──────────────────────
Invalid token            │ Token hash found?          │ 400: Invalid token
Token expired            │ Expires_at > now?          │ 400: Token expired
Token already used       │ Used field = false?        │ 400: Token used
─────────────────────────┼────────────────────────────┼──────────────────────
Weak password            │ Django validators?         │ 400: Password weak
Same as old password     │ Different password?        │ 400: Same password
Password in history      │ Not in last 5?             │ 400: Recently used
─────────────────────────┼────────────────────────────┼──────────────────────
Wrong old password       │ check_password()?          │ 400: Old password wrong
Not authenticated        │ Auth token present?        │ 401: Not authenticated
Permission denied        │ User owns account?         │ 403: Forbidden
```

---

## Database Schema

```
┌─────────────────────────────────────────┐
│         PasswordResetToken              │
├─────────────────────────────────────────┤
│ id (BigAutoField)                       │
│ user_id (FK → User)                     │
│ token_hash (CharField, unique, indexed) │
│ created_at (DateTime, indexed)          │
│ expires_at (DateTime, indexed)          │
│ used (BooleanField)                     │
│ used_at (DateTime, nullable)            │
│ ip_address (GenericIPAddressField)      │
│ user_agent (CharField)                  │
│                                         │
│ Composite Index:                        │
│ (token_hash, used, expires_at)          │
└─────────────────────────────────────────┘
           │
           │ 1:N
           ▼
┌─────────────────────────────────────────┐
│            User (existing)              │
├─────────────────────────────────────────┤
│ id (BigAutoField)                       │
│ email (EmailField, unique)              │
│ password (CharField)                    │
│ password_last_changed (DateTime)        │
│ is_active (BooleanField)                │
│ ...                                     │
└─────────────────────────────────────────┘
           │
           │ 1:N
           ▼
┌─────────────────────────────────────────┐
│        PasswordHistory (SCRUM-9)        │
├─────────────────────────────────────────┤
│ id (BigAutoField)                       │
│ user_id (FK → User)                     │
│ password_hash (CharField, hashed)       │
│ created_at (DateTime)                   │
│                                         │
│ Index: (user_id, -created_at)          │
│ Policy: Keep last 5 entries only        │
└─────────────────────────────────────────┘
```

---

## Throttling Configuration

```
┌──────────────────────────────────────────┐
│       RATE LIMITING RULES                │
├──────────────────────────────────────────┤
│                                          │
│  Login                   5 attempts      │
│  per 15 minutes per IP                   │
│                                          │
│  Registration            3 attempts      │
│  per hour per IP                         │
│                                          │
│  Password Reset Request  3 attempts      │
│  per hour per IP                         │
│  (Prevents email bombing)                │
│                                          │
│  Password Reset Confirm  5 attempts      │
│  per 15 minutes per IP                   │
│  (Prevents token brute-forcing)          │
│                                          │
│  Password Change         5 attempts      │
│  per 15 minutes per IP                   │
│  (Same as login)                         │
│                                          │
└──────────────────────────────────────────┘
```

This architecture ensures security at every layer while maintaining user experience and system performance.
