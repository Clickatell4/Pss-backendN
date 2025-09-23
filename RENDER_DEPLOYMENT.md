# Render Deployment Guide for PSS Backend

## 🚀 Quick Deploy

### Option 1: One-Click Deploy (Using render.yaml)
1. Fork this repository to your GitHub account
2. Go to [Render Dashboard](https://dashboard.render.com)
3. Click "New" → "Blueprint"
4. Connect your GitHub repo
5. Render will automatically read `render.yaml` and set up:
   - Web Service for the Django API
   - PostgreSQL Database
   - All necessary environment variables

### Option 2: Manual Setup

## 📋 Step-by-Step Manual Deployment

### 1. Create PostgreSQL Database
1. In Render Dashboard → "New" → "PostgreSQL"
2. Name: `pss-database`
3. Database Name: `pss_database`
4. User: `pss_user`
5. Region: Choose closest to your users
6. Plan: Starter (free) or Standard (production)

### 2. Create Web Service
1. In Render Dashboard → "New" → "Web Service"
2. Connect your GitHub repository
3. Configure:
   - **Name**: `pss-backend`
   - **Runtime**: Python 3
   - **Build Command**: `./build.sh`
   - **Start Command**: `./start.sh`
   - **Plan**: Starter (free) or Standard (production)

### 3. Environment Variables

Set these in Render Dashboard → Your Service → Environment:

#### Required Variables
```
SECRET_KEY=<auto-generate-on-render>
DEBUG=false
PYTHON_VERSION=3.11.9
```

#### Database (Auto-configured if using Render PostgreSQL)
```
DB_NAME=<auto-from-database>
DB_USER=<auto-from-database>
DB_PASSWORD=<auto-from-database>
DB_HOST=<auto-from-database>
DB_PORT=5432
DB_SSL=true
```

#### Domains & CORS
```
ALLOWED_HOSTS=your-app-name.onrender.com,your-custom-domain.com
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com,https://your-app.vercel.app
```

#### Security (Production)
```
SECURE_SSL_REDIRECT=true
CSRF_COOKIE_SECURE=true
SESSION_COOKIE_SECURE=true
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=true
SECURE_HSTS_PRELOAD=true
```

#### Optional: Auto-create Superuser
```
DJANGO_SUPERUSER_EMAIL=admin@capaciti.org.za
DJANGO_SUPERUSER_PASSWORD=<secure-password>
```

## 🔧 Configuration Details

### Build Process
The `build.sh` script will:
1. Install Python dependencies
2. Collect static files
3. Run database migrations

### Start Process
The `start.sh` script will:
1. Run any pending migrations
2. Create superuser (if configured)
3. Start Gunicorn server with optimized settings

### Gunicorn Configuration
- Optimized for Render's environment
- Auto-scaling workers based on CPU cores
- Proper logging and timeout settings
- Memory leak prevention

## 🌐 Post-Deployment

### 1. Verify Deployment
- Check logs in Render Dashboard
- Test API endpoints: `https://your-app.onrender.com/api/auth/login/`
- Access Django admin: `https://your-app.onrender.com/admin/`

### 2. Update Frontend CORS
Update your frontend to use the new backend URL:
```
https://your-app-name.onrender.com/api/
```

### 3. Custom Domain (Optional)
1. In Render Dashboard → Your Service → Settings
2. Add your custom domain
3. Update `ALLOWED_HOSTS` environment variable

## 📊 Monitoring & Scaling

### Free Tier Limitations
- Service sleeps after 15 minutes of inactivity
- 512MB RAM, shared CPU
- 100GB bandwidth/month

### Upgrading for Production
1. Change plan to "Standard" or "Pro"
2. Add monitoring and alerts
3. Set up backup strategy for database

## 🔒 Security Checklist

- ✅ SECRET_KEY is auto-generated
- ✅ DEBUG=false in production
- ✅ HTTPS enforced
- ✅ Security headers enabled
- ✅ Database SSL enabled
- ✅ CORS properly configured

## 🚨 Troubleshooting

### Common Issues
1. **Build fails**: Check Python version in `runtime.txt`
2. **Database connection fails**: Verify DB environment variables
3. **Static files not loading**: Check `ALLOWED_HOSTS` setting
4. **CORS errors**: Update `CORS_ALLOWED_ORIGINS`

### Logs
Access logs in Render Dashboard → Your Service → Logs

### Database Access
Use Render's built-in database shell or connect with external tools using the provided connection string.

## 📞 Support

For deployment issues:
1. Check Render's [documentation](https://render.com/docs)
2. Review build and runtime logs
3. Verify environment variables match requirements