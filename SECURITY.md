# 🔒 Security Documentation

## Overview
This document explains the security measures implemented to prevent unauthorized access to admin features.

## 🛡️ Security Measures

### 1. **Role-Based Access Control (RBAC)**
- **Only 2 roles allowed:** `USER` and `ADMIN`
- **Role determination:** Based on EMAIL address, not database value
- **Admin access:** Only `webnox@admin.com` can get `ADMIN` role

### 2. **Email-Based Role Assignment**
```javascript
// SECURITY: Only webnox@admin.com can have ADMIN role
const finalRole = user.email === 'webnox@admin.com' ? 'ADMIN' : 'USER';
```

**Why this is secure:**
- Role is determined at login time based on email
- Even if someone manipulates the database, they can't get admin access
- Only the specific email `webnox@admin.com` can be admin

### 3. **Multi-Layer Validation**

#### Login Layer:
```javascript
// Check 1: Validate credentials
const user = await this.userService.validateCredentials({ email, password });

// Check 2: Verify admin access
if (user.role === 'ADMIN' && email !== 'webnox@admin.com') {
  // Block access and log security alert
}
```

#### Endpoint Layer:
```javascript
// Check 1: Authentication required
if (!req.user) {
  return res.status(401).json({ error: 'Authentication required' });
}

// Check 2: Admin role required
if (req.user.role !== 'ADMIN') {
  return res.status(403).json({ error: 'Admin privileges required' });
}

// Check 3: Specific admin email required
if (req.user.email !== 'webnox@admin.com') {
  return res.status(403).json({ error: 'Admin access denied' });
}
```

## 🧪 Testing Security

### Test Cases:

#### 1. **Regular User Login**
```bash
POST /api/auth/login
{
  "email": "user1@cyberix.com",
  "password": "user123"
}
```
**Expected:** Role = `USER`, Cannot access admin endpoints

#### 2. **Admin Login**
```bash
POST /api/auth/login
{
  "email": "webnox@admin.com",
  "password": "12345"
}
```
**Expected:** Role = `ADMIN`, Can access admin endpoints

#### 3. **Login Attempt Blocking Test**
```bash
# Attempt 1
POST /api/auth/login
{
  "email": "test@example.com",
  "password": "wrong1"
}
# Expected: 401 - Invalid credentials. 2 attempts remaining.

# Attempt 2
POST /api/auth/login
{
  "email": "test@example.com",
  "password": "wrong2"
}
# Expected: 401 - Invalid credentials. 1 attempt remaining.

# Attempt 3
POST /api/auth/login
{
  "email": "test@example.com",
  "password": "wrong3"
}
# Expected: 423 - Account blocked after 3 failed attempts. Try again in 5 minutes.

# Attempt 4 (while blocked)
POST /api/auth/login
{
  "email": "test@example.com",
  "password": "correct"
}
# Expected: 423 - Account temporarily blocked. Try again in X minutes.
```

#### 4. **Check Block Status**
```bash
GET /api/auth/block-status/test@example.com
```
**Expected:** Block status with remaining time

#### 5. **Unauthorized Admin Access**
```bash
GET /api/auth/login-logs
Cookie: accessToken=user_token
```
**Expected:** `403 Forbidden`

## 🚨 Security Alerts

### Logged Events:
1. **Unauthorized admin login attempts**
2. **Failed authentication attempts**
3. **Admin endpoint access attempts**
4. **Single device login violations**

### Example Security Log:
```
SECURITY ALERT: Unauthorized admin login attempt - only webnox@admin.com can login as admin
User: fakeadmin@admin.com
IP: 192.168.1.100
User-Agent: Mozilla/5.0...
```

## 🔐 How to Prevent Unauthorized Access

### 1. **Database Security**
- Role is not stored in database for security
- Role is determined by email at runtime
- Even if database is compromised, admin access is protected

### 2. **API Security**
- All admin endpoints require authentication
- All admin endpoints verify specific email
- Failed attempts are logged and monitored

### 3. **Session Security**
- Single device login enforcement
- Secure HTTP-only cookies
- Session expiration after 7 days

### 4. **Network Security**
- All admin actions are logged with IP address
- Failed attempts are tracked and can be blocked
- Real-time monitoring of admin access

## 📊 Monitoring

### Key Metrics to Monitor:
1. **Failed login attempts** (especially admin)
2. **Unauthorized admin access attempts**
3. **Suspicious IP addresses**
4. **Multiple failed attempts from same IP**

### Alert Conditions:
- More than 3 failed admin login attempts
- Admin access from unknown IP
- Multiple admin access attempts in short time

## ✅ Security Checklist

- [x] Role determined by email, not database
- [x] Only `webnox@admin.com` can be admin
- [x] All admin endpoints protected
- [x] Failed attempts logged
- [x] Single device login enforced
- [x] Secure cookie implementation
- [x] Multi-layer validation
- [x] Real-time monitoring

## 🚀 Running Security Tests

```bash
# Install dependencies
npm install axios

# Run security tests
node test-security.js
```

This will test all security measures and show you exactly what happens when someone tries to access admin features without proper authorization.
