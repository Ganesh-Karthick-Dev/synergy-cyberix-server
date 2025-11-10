# GitHub OAuth API Documentation

## Overview
This document provides complete API documentation for GitHub OAuth authentication in the Cyberix Security Scanner backend.

## Base URL
```
http://localhost:9000
```

## Prerequisites

### 1. GitHub OAuth App Setup
1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: Your App Name
   - **Homepage URL**: `http://localhost:3000` (your frontend URL)
   - **Authorization callback URL**: `http://localhost:9000/api/auth/github/callback`
4. Copy the **Client ID** and **Client Secret**

### 2. Environment Variables
Add these to your `.env` file:

```env
# GitHub OAuth Configuration
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
BACKEND_URL=http://localhost:9000
GITHUB_CALLBACK_URL=http://localhost:9000/api/auth/github/callback
FRONTEND_URL=http://localhost:3000
```

---

## API Endpoints

### 1. Initiate GitHub OAuth Login

**Endpoint:** `GET /api/auth/github`

**Description:** Initiates the GitHub OAuth flow. Redirects user to GitHub's authorization page.

**Query Parameters:**
- `redirect` (optional): URL to redirect to after successful login (default: `/`)

**Example Request:**
```bash
GET /api/auth/github?redirect=/dashboard
```

**Response:**
- **Status Code:** `302 Found`
- **Location:** Redirects to GitHub OAuth authorization page

**Frontend Implementation:**
```javascript
// React/Next.js Example
const handleGitHubLogin = () => {
  window.location.href = 'http://localhost:9000/api/auth/github?redirect=/dashboard';
};

// Or with fetch (but redirect is better)
const handleGitHubLogin = async () => {
  const response = await fetch('http://localhost:9000/api/auth/github?redirect=/dashboard', {
    method: 'GET',
    credentials: 'include', // Important for cookies
    redirect: 'manual' // Handle redirect manually
  });
  
  if (response.type === 'opaqueredirect') {
    window.location.href = response.url;
  }
};
```

---

### 2. GitHub OAuth Callback

**Endpoint:** `GET /api/auth/github/callback`

**Description:** Handles the callback from GitHub after user authorization. This endpoint:
1. Validates the authorization code
2. Exchanges code for access token
3. Fetches user info from GitHub
4. Creates/updates user in database
5. Generates JWT tokens
6. Sets authentication cookies
7. Redirects to frontend

**Query Parameters (from GitHub):**
- `code`: Authorization code from GitHub
- `state`: State parameter (if used)

**Response:**
- **Status Code:** `302 Found`
- **Location:** Redirects to frontend URL (with success) or error page

**Success Redirect:**
```
http://localhost:3000/?github_auth=success
```

**Error Redirect:**
```
http://localhost:3000/signin?error=GitHub authentication failed
```

**Note:** This endpoint is called automatically by GitHub. You don't need to call it directly from your frontend.

---

## OAuth Flow Diagram

```
┌─────────┐                    ┌──────────┐                    ┌─────────┐
│Frontend│                    │ Backend  │                    │ GitHub  │
└────┬────┘                    └────┬─────┘                    └────┬────┘
     │                              │                              │
     │ 1. GET /api/auth/github      │                              │
     │────────────────────────────>│                              │
     │                              │                              │
     │                              │ 2. Redirect to GitHub       │
     │                              │─────────────────────────────>│
     │                              │                              │
     │                              │ 3. User authorizes           │
     │                              │<─────────────────────────────│
     │                              │                              │
     │                              │ 4. Callback with code        │
     │                              │<─────────────────────────────│
     │                              │                              │
     │                              │ 5. Exchange code for token    │
     │                              │─────────────────────────────>│
     │                              │                              │
     │                              │ 6. Get user info             │
     │                              │─────────────────────────────>│
     │                              │                              │
     │                              │ 7. Create/update user        │
     │                              │    Generate JWT tokens        │
     │                              │    Set cookies                │
     │                              │                              │
     │ 8. Redirect with cookies     │                              │
     │<─────────────────────────────│                              │
     │                              │                              │
```

---

## Frontend Integration Guide

### React/Next.js Example

```jsx
import React from 'react';

const LoginPage = () => {
  const handleGitHubLogin = () => {
    // Redirect to backend OAuth endpoint
    // The backend will handle the OAuth flow and redirect back
    window.location.href = `${process.env.NEXT_PUBLIC_API_URL}/api/auth/github?redirect=/dashboard`;
  };

  return (
    <div>
      <h1>Login</h1>
      <button onClick={handleGitHubLogin}>
        Sign in with GitHub
      </button>
    </div>
  );
};

export default LoginPage;
```

### Handling Callback in Frontend

```jsx
// pages/callback.js or pages/dashboard.js
import { useEffect } from 'react';
import { useRouter } from 'next/router';

const CallbackPage = () => {
  const router = useRouter();

  useEffect(() => {
    // Check if user is authenticated by checking cookies
    const checkAuth = async () => {
      try {
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/auth/profile`, {
          credentials: 'include', // Important: include cookies
        });

        if (response.ok) {
          const data = await response.json();
          console.log('User authenticated:', data);
          router.push('/dashboard');
        } else {
          router.push('/login');
        }
      } catch (error) {
        console.error('Auth check failed:', error);
        router.push('/login');
      }
    };

    checkAuth();
  }, [router]);

  return <div>Loading...</div>;
};
```

### Vue.js Example

```vue
<template>
  <div>
    <button @click="handleGitHubLogin">Sign in with GitHub</button>
  </div>
</template>

<script>
export default {
  methods: {
    handleGitHubLogin() {
      window.location.href = `${process.env.VUE_APP_API_URL}/api/auth/github?redirect=/dashboard`;
    }
  }
}
</script>
```

---

## Authentication Cookies

After successful GitHub OAuth login, the backend sets these cookies:

1. **accessToken** (HttpOnly)
   - JWT access token
   - Expires: 7 days
   - Path: `/`
   - SameSite: `lax` (development) / `strict` (production)

2. **refreshToken** (HttpOnly)
   - JWT refresh token
   - Expires: 30 days
   - Path: `/`
   - SameSite: `lax` (development) / `strict` (production)

3. **isAuthenticated** (Not HttpOnly)
   - Value: `"true"`
   - Can be read by JavaScript
   - Expires: 7 days

### Using Cookies in API Requests

```javascript
// All authenticated requests should include credentials
fetch('http://localhost:9000/api/auth/profile', {
  method: 'GET',
  credentials: 'include', // Important: sends cookies
  headers: {
    'Content-Type': 'application/json',
  }
});
```

---

## User Data Structure

After successful GitHub OAuth login, user data is stored in the database:

```typescript
{
  id: string;              // User ID (CUID)
  email: string;           // Email from GitHub
  username: string | null;  // GitHub username
  githubId: string;        // GitHub user ID
  firstName: string | null;  // From GitHub profile
  lastName: string | null;  // From GitHub profile
  avatar: string | null;    // GitHub avatar URL
  role: 'USER' | 'ADMIN';  // User role
  status: 'ACTIVE';        // Account status
  emailVerified: true;      // Auto-verified via GitHub
  createdAt: Date;
  updatedAt: Date;
}
```

---

## Error Handling

### Common Errors

1. **GitHub OAuth Not Configured**
   ```json
   {
     "success": false,
     "error": {
       "message": "GitHub OAuth is not configured",
       "statusCode": 503
     }
   }
   ```
   **Solution:** Add `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` to `.env`

2. **No Email in GitHub Profile**
   ```
   Redirect: /signin?error=No email found in GitHub profile
   ```
   **Solution:** User must have a public email in GitHub settings

3. **Account Not Active**
   ```
   Redirect: /signin?error=Account is not active
   ```
   **Solution:** Contact admin to activate account

4. **Authentication Failed**
   ```
   Redirect: /signin?error=GitHub authentication failed
   ```
   **Solution:** Check GitHub OAuth app configuration

---

## Testing the API

### Using cURL

```bash
# 1. Initiate OAuth (will redirect to GitHub)
curl -L "http://localhost:9000/api/auth/github?redirect=/dashboard"

# 2. After GitHub authorization, check profile (requires cookies from step 1)
curl -X GET "http://localhost:9000/api/auth/profile" \
  -H "Cookie: accessToken=your-token-here" \
  --cookie-jar cookies.txt \
  --cookie cookies.txt
```

### Using Postman

1. **Initiate OAuth:**
   - Method: `GET`
   - URL: `http://localhost:9000/api/auth/github?redirect=/dashboard`
   - Follow redirects: Enabled
   - After GitHub login, you'll be redirected back with cookies set

2. **Check Profile:**
   - Method: `GET`
   - URL: `http://localhost:9000/api/auth/profile`
   - Cookies: Use cookies from previous request

---

## Security Considerations

1. **HTTPS in Production:** Always use HTTPS in production
2. **Cookie Security:** Cookies are HttpOnly and Secure in production
3. **State Parameter:** Consider adding state parameter for CSRF protection
4. **Token Expiration:** Access tokens expire in 7 days, refresh tokens in 30 days
5. **Session Management:** Multiple sessions are allowed (multiple devices)

---

## Additional Endpoints

### Get User Profile (After Login)

**Endpoint:** `GET /api/auth/profile`

**Headers:**
```
Cookie: accessToken=<token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "user-id",
    "email": "user@example.com",
    "username": "github-username",
    "firstName": "John",
    "lastName": "Doe",
    "avatar": "https://avatars.githubusercontent.com/u/123456",
    "role": "USER",
    "status": "ACTIVE",
    "emailVerified": true,
    "githubId": "123456"
  },
  "message": "Profile retrieved successfully"
}
```

### Logout

**Endpoint:** `POST /api/auth/logout`

**Headers:**
```
Cookie: accessToken=<token>
```

**Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

---

## Complete API List for Frontend

### GitHub OAuth Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|----------------|
| `GET` | `/api/auth/github` | Initiate GitHub OAuth login | No |
| `GET` | `/api/auth/github/callback` | GitHub OAuth callback (handled by GitHub) | No |

### User Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|----------------|
| `GET` | `/api/auth/profile` | Get current user profile | Yes |
| `POST` | `/api/auth/logout` | Logout current user | Yes |
| `POST` | `/api/auth/refresh` | Refresh access token | No (uses refresh token cookie) |

---

## Quick Start Checklist

- [ ] Create GitHub OAuth App
- [ ] Add `GITHUB_CLIENT_ID` to `.env`
- [ ] Add `GITHUB_CLIENT_SECRET` to `.env`
- [ ] Set `GITHUB_CALLBACK_URL` in `.env`
- [ ] Set `FRONTEND_URL` in `.env`
- [ ] Run database migrations: `npm run db:push`
- [ ] Start backend server: `npm run dev`
- [ ] Test OAuth flow in frontend
- [ ] Verify cookies are set after login
- [ ] Test authenticated endpoints

---

## Support

For issues or questions:
1. Check backend logs for detailed error messages
2. Verify GitHub OAuth app configuration
3. Ensure environment variables are set correctly
4. Check that callback URL matches GitHub OAuth app settings

---

## Example Complete Flow

```javascript
// 1. User clicks "Sign in with GitHub"
const loginWithGitHub = () => {
  const redirectUrl = encodeURIComponent('/dashboard');
  window.location.href = `http://localhost:9000/api/auth/github?redirect=${redirectUrl}`;
};

// 2. After redirect back from GitHub, check if authenticated
const checkAuth = async () => {
  try {
    const response = await fetch('http://localhost:9000/api/auth/profile', {
      credentials: 'include',
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log('Logged in as:', data.data.email);
      // User is authenticated, redirect to dashboard
      window.location.href = '/dashboard';
    } else {
      // Not authenticated, show login page
      console.log('Not authenticated');
    }
  } catch (error) {
    console.error('Auth check failed:', error);
  }
};

// 3. Logout
const logout = async () => {
  try {
    await fetch('http://localhost:9000/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
    });
    window.location.href = '/login';
  } catch (error) {
    console.error('Logout failed:', error);
  }
};
```

