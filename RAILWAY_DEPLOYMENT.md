# Railway Deployment Guide for PSS Backend

## 🚀 Quick Deploy (No Credit Card Required)

### Step 1: Deploy to Railway
1. Go to [Railway.app](https://railway.app)
2. Sign up with GitHub (free, no card required)
3. Click "Deploy from GitHub repo"
4. Select your `Pss-backendN` repository
5. Railway will automatically detect Django and deploy

### Step 2: Add PostgreSQL Database
1. In your Railway project dashboard
2. Click "New" → "Database" → "PostgreSQL"
3. Railway will auto-connect it to your Django app

### Step 3: Configure Environment Variables
In Railway Dashboard → Your Service → Variables, add:

```
SECRET_KEY=your-auto-generated-secret-key
DEBUG=false
ALLOWED_HOSTS=$RAILWAY_PUBLIC_DOMAIN
CORS_ALLOWED_ORIGINS=https://pss-frontend-ebon.vercel.app
DB_SSL=true
SECURE_SSL_REDIRECT=true
CSRF_COOKIE_SECURE=true
SESSION_COOKIE_SECURE=true
```

### Step 4: Deploy
Railway will automatically build and deploy your app.

## 🔗 Your URLs
- API: `https://your-app-name.up.railway.app/api/`
- Admin: `https://your-app-name.up.railway.app/admin/`

## 📊 Free Tier Limits
- $5 credit per month (enough for small apps)
- Automatic sleep after 30 minutes of inactivity
- Shared resources

No credit card required for the free tier!