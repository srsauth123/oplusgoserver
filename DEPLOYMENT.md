# Go Server Deployment Guide

## Overview
This Go server provides REST APIs for the OPLUS Admin Dashboard and handles:
- User authentication & JWT tokens
- Sign operations
- Flash/ROM firmware management
- Server management
- Certificate distribution

## Prerequisites
- Go 1.21+
- MySQL database (5.7+)
- config.yaml with proper credentials

## Local Development

### 1. Install Dependencies
```bash
cd go-server
go mod download
```

### 2. Setup Database
Create MySQL database:
```sql
CREATE DATABASE auth;
```

The server auto-creates all required tables on startup.

### 3. Run Server
```bash
go run main.go config.yaml
# Or with default config.yaml in same directory
go run main.go
```

Server starts on `http://localhost:8080`

## Production Deployment

### Option 1: Railway (Easiest)

**1. Go to https://railway.app**
- Sign up with GitHub

**2. Create New Project**
- Click "+New" → "GitHub Repo"
- Select your `oplus-admin-server` repository

**3. Add Environment Variables**
In Railway dashboard, add:
```
DATABASE_HOST=your-mysql-host.railway.internal
DATABASE_USER=auth
DATABASE_PASSWORD=RCGeAS8L3YwdSfGN
DATABASE_NAME=auth
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password
JWT_SECRET=generate-random-secret-key
PORT=8080
```

**4. Configure Build & Deploy**
- Build Command: `go build -o server main.go`
- Start Command: `./server config.yaml`

**5. Deploy**
Railway auto-deploys on git push

**Your API URL:**
```
https://your-app.railway.app
```

---

### Option 2: Render (Free Alternative)

**1. Go to https://render.com**
- Sign up

**2. Create Web Service**
- New → Web Service
- Connect GitHub repo
- Root directory: `go-server`

**3. Configure**
- Build: `go mod download && go build -o server .`
- Start: `./server config.yaml`
- Environment: Add same vars as Railway

**4. Deploy**

---

### Option 3: Docker (Any Host)

**1. Build Image**
```bash
docker build -t oplus-server .
```

**2. Run Container**
```bash
docker run -p 8080:8080 \
  -e DATABASE_HOST=your-db-host \
  -e DATABASE_USER=auth \
  -e DATABASE_PASSWORD=your-password \
  oplus-server
```

---

## API Endpoints

### Admin Endpoints
```
POST   /v1/admin/login/login           - Admin login
GET    /v1/admin/dashboard/stats       - Dashboard stats
GET    /v1/admin/servers/list          - List servers
POST   /v1/admin/servers/create        - Create server
...
```

### Public Endpoints
```
POST   /api/platform/login             - Platform login
POST   /api/tools/login                - Tools login
POST   /api/sign/sign                  - Signing service
GET    /api/flash/get_versions         - Firmware versions
...
```

## Frontend Integration

Update your frontend's API base URL to point to the deployed server:

**Environment variable in frontend:**
```
VITE_API_URL=https://your-app.railway.app
```

Or hardcode in API client:
```javascript
const API_BASE_URL = process.env.VITE_API_URL || 'https://your-app.railway.app';
```

## Monitoring

View logs in deployment platform:
- **Railway**: Dashboard → Logs
- **Render**: Logs tab
- **Docker**: `docker logs container-id`

## Database Backup

```bash
# Export
mysqldump -h host -u user -p database > backup.sql

# Import
mysql -h host -u user -p database < backup.sql
```

## Troubleshooting

**"Failed to connect database"**
- Check DATABASE_HOST, USER, PASSWORD
- Ensure MySQL is accessible from server
- Check database firewall rules

**"JWT token invalid"**
- Regenerate JWT_SECRET
- Clear browser cookies
- Re-login

**"Port already in use"**
- Change PORT environment variable
- Or kill process: `lsof -ti:8080 | xargs kill -9`

## Security Checklist

- ✅ Change default admin password
- ✅ Generate strong JWT_SECRET
- ✅ Use HTTPS/SSL in production
- ✅ Enable database backups
- ✅ Setup firewall rules
- ✅ Hide config.yaml (add to .gitignore)
- ✅ Rotate API tokens regularly
