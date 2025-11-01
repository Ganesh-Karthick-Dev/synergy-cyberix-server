# Development and Production Mode Configuration

## 🚀 **Mode System Overview**

The application now supports two modes:
- **Development Mode**: Relaxed security for easier development
- **Production Mode**: Full security features enabled

## 📁 **Environment Files**

### **Development Mode (.env.development)**
```env
# Development Mode Configuration
NODE_ENV=development
APP_MODE=development

# Security Settings - DISABLED in development
SINGLE_DEVICE_LOGIN=false
LOGIN_BLOCKING=false
EMAIL_NOTIFICATIONS=false
ADMIN_ACCESS_CONTROL=true

# Server Configuration
PORT=9000

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=12345
DB_NAME=cyberix

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here-dev
JWT_EXPIRES_IN=7d
JWT_REFRESH_SECRET=your-super-secret-refresh-key-here-dev
JWT_REFRESH_EXPIRES_IN=30d

# Session Configuration
SESSION_SECRET=your-super-secret-session-key-here-dev

# CORS Configuration
CORS_ORIGIN=http://localhost:3000,http://localhost:3001

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=1000

# Email Configuration (Optional in dev)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=ganeshkarthik18697@gmail.com
SMTP_PASS=wvrf mwak wlmk eevx

# Frontend URL
FRONTEND_URL=http://localhost:3000
```

### **Production Mode (.env.production)**
```env
# Production Mode Configuration
NODE_ENV=production
APP_MODE=production

# Security Settings - ENABLED in production
SINGLE_DEVICE_LOGIN=true
LOGIN_BLOCKING=true
EMAIL_NOTIFICATIONS=true
ADMIN_ACCESS_CONTROL=true

# Server Configuration
PORT=9000

# Database Configuration
DB_HOST=your-production-db-host
DB_PORT=5432
DB_USERNAME=your-production-db-user
DB_PASSWORD=your-production-db-password
DB_NAME=cyberix

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-key-here-prod
JWT_EXPIRES_IN=7d
JWT_REFRESH_SECRET=your-super-secure-refresh-key-here-prod
JWT_REFRESH_EXPIRES_IN=30d

# Session Configuration
SESSION_SECRET=your-super-secure-session-key-here-prod

# CORS Configuration
CORS_ORIGIN=https://yourdomain.com,https://admin.yourdomain.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-production-email@gmail.com
SMTP_PASS=your-production-app-password

# Frontend URL
FRONTEND_URL=https://yourdomain.com
```

## 🔧 **How to Switch Modes**

### **Development Mode (Current)**
```bash
# Set environment variables
export APP_MODE=development
export SINGLE_DEVICE_LOGIN=false
export LOGIN_BLOCKING=false
export EMAIL_NOTIFICATIONS=false

# Or create .env.development file with above settings
# Then run:
npm run dev
```

### **Production Mode**
```bash
# Set environment variables
export APP_MODE=production
export SINGLE_DEVICE_LOGIN=true
export LOGIN_BLOCKING=true
export EMAIL_NOTIFICATIONS=true

# Or create .env.production file with above settings
# Then run:
npm run start
```

## 📊 **Mode Comparison**

| Feature | Development Mode | Production Mode |
|---------|------------------|-----------------|
| **Single Device Login** | ❌ Disabled | ✅ Enabled |
| **Login Blocking** | ❌ Disabled | ✅ Enabled |
| **Email Notifications** | ❌ Disabled | ✅ Enabled |
| **Admin Access Control** | ✅ Enabled | ✅ Enabled |
| **Rate Limiting** | Relaxed (1000 req/15min) | Strict (100 req/15min) |
| **Error Messages** | Simple | Detailed with blocking info |
| **Security Logs** | Basic | Comprehensive |

## 🚀 **Quick Commands**

### **Start in Development Mode**
```bash
APP_MODE=development npm run dev
```

### **Start in Production Mode**
```bash
APP_MODE=production npm run dev
```

### **Test Mode Settings**
```bash
# Check current mode
curl http://localhost:9000/health

# The response will show the current environment and mode
```

## 🔍 **Verification**

### **Development Mode Behavior:**
- ✅ Multiple devices can login simultaneously
- ✅ No account blocking after failed attempts
- ✅ No email notifications sent
- ✅ Simple error messages
- ✅ Relaxed rate limiting

### **Production Mode Behavior:**
- ✅ Single device login enforced
- ✅ Account blocking after 3 failed attempts
- ✅ Email notifications for suspicious activity
- ✅ Detailed error messages with attempt counts
- ✅ Strict rate limiting

## 🎯 **When to Use Each Mode**

### **Development Mode:**
- Local development
- Testing features
- Debugging
- Multiple developers working simultaneously

### **Production Mode:**
- Live production environment
- User-facing application
- Security-critical deployments
- Final testing before release
