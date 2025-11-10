# GitHub OAuth API - Quick Reference

## Base URL
```
http://localhost:9000
```

## API Endpoints

### 1. Initiate GitHub OAuth Login
```
GET /api/auth/github?redirect=/dashboard
```
**Description:** Redirects user to GitHub OAuth authorization page

**Query Parameters:**
- `redirect` (optional): URL to redirect to after successful login (default: `/`)

**Example:**
```javascript
window.location.href = 'http://localhost:9000/api/auth/github?redirect=/dashboard';
```

**Response:** `302 Redirect` to GitHub OAuth page

---

### 2. GitHub OAuth Callback
```
GET /api/auth/github/callback
```
**Description:** Handles callback from GitHub (called automatically by GitHub)

**Query Parameters (from GitHub):**
- `code`: Authorization code
- `state`: State parameter (if used)

**Response:** `302 Redirect` to frontend with cookies set

**Success:** Redirects to `FRONTEND_URL/?github_auth=success`
**Error:** Redirects to `FRONTEND_URL/signin?error=<error_message>`

---

## Authentication Cookies (Set After Login)

After successful GitHub OAuth login, these cookies are automatically set:

1. **accessToken** (HttpOnly, 7 days)
2. **refreshToken** (HttpOnly, 30 days)
3. **isAuthenticated** (Not HttpOnly, 7 days)

---

## Related Endpoints

### Get User Profile
```
GET /api/auth/profile
```
**Headers:** `Cookie: accessToken=<token>`
**Auth Required:** Yes

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "user-id",
    "email": "user@example.com",
    "username": "github-username",
    "githubId": "123456",
    "avatar": "https://avatars.githubusercontent.com/u/123456",
    "role": "USER",
    "status": "ACTIVE"
  }
}
```

### Logout
```
POST /api/auth/logout
```
**Headers:** `Cookie: accessToken=<token>`
**Auth Required:** Yes

**Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

### Refresh Token
```
POST /api/auth/refresh
```
**Headers:** `Cookie: refreshToken=<token>`
**Auth Required:** No (uses refresh token cookie)

**Response:**
```json
{
  "success": true,
  "message": "Tokens refreshed successfully"
}
```

---

## Frontend Integration Example

### React/Next.js
```jsx
// Login button
const handleGitHubLogin = () => {
  window.location.href = `${process.env.NEXT_PUBLIC_API_URL}/api/auth/github?redirect=/dashboard`;
};

// Check authentication
const checkAuth = async () => {
  const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/auth/profile`, {
    credentials: 'include', // Important: include cookies
  });
  
  if (response.ok) {
    const data = await response.json();
    console.log('Authenticated:', data.data.email);
  }
};

// Logout
const logout = async () => {
  await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  });
  window.location.href = '/login';
};
```

### Vue.js
```vue
<template>
  <button @click="loginWithGitHub">Sign in with GitHub</button>
</template>

<script>
export default {
  methods: {
    loginWithGitHub() {
      window.location.href = `${process.env.VUE_APP_API_URL}/api/auth/github?redirect=/dashboard`;
    }
  }
}
</script>
```

### Vanilla JavaScript
```javascript
// Login
function loginWithGitHub() {
  window.location.href = 'http://localhost:9000/api/auth/github?redirect=/dashboard';
}

// Check auth
async function checkAuth() {
  const response = await fetch('http://localhost:9000/api/auth/profile', {
    credentials: 'include',
  });
  
  if (response.ok) {
    const data = await response.json();
    console.log('Authenticated:', data.data.email);
    return true;
  }
  return false;
}

// Logout
async function logout() {
  await fetch('http://localhost:9000/api/auth/logout', {
    method: 'POST',
    credentials: 'include',
  });
  window.location.href = '/login';
}
```

---

## Environment Variables Required

```env
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:9000/api/auth/github/callback
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:9000
```

---

## OAuth Flow

1. User clicks "Sign in with GitHub"
2. Frontend redirects to: `GET /api/auth/github?redirect=/dashboard`
3. Backend redirects to GitHub OAuth page
4. User authorizes on GitHub
5. GitHub redirects to: `GET /api/auth/github/callback?code=<code>`
6. Backend exchanges code for token, creates/updates user, sets cookies
7. Backend redirects to: `FRONTEND_URL/?github_auth=success`
8. Frontend checks authentication using cookies

---

## Important Notes

1. **Always use `credentials: 'include'`** in fetch requests to send cookies
2. **Callback URL must match** GitHub OAuth app settings exactly
3. **Cookies are HttpOnly** (except `isAuthenticated`) for security
4. **Multiple sessions allowed** (user can login from multiple devices)
5. **Tokens expire:** Access token (7 days), Refresh token (30 days)

---

## Error Handling

If OAuth fails, user is redirected to:
```
FRONTEND_URL/signin?error=<error_message>
```

Common errors:
- `GitHub OAuth is not configured` - Check environment variables
- `No email found in GitHub profile` - User must have public email
- `Account is not active` - Contact admin
- `GitHub authentication failed` - Check GitHub OAuth app configuration

---

## Testing

### Using Browser
1. Navigate to: `http://localhost:9000/api/auth/github?redirect=/dashboard`
2. Authorize on GitHub
3. Check cookies in browser DevTools
4. Verify redirect to frontend

### Using cURL
```bash
# Initiate OAuth (will redirect to GitHub)
curl -L "http://localhost:9000/api/auth/github?redirect=/dashboard" \
  --cookie-jar cookies.txt

# After GitHub login, check profile
curl -X GET "http://localhost:9000/api/auth/profile" \
  --cookie cookies.txt
```

---

## Complete API List

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|----------------|
| `GET` | `/api/auth/github` | Initiate GitHub OAuth | No |
| `GET` | `/api/auth/github/callback` | GitHub OAuth callback | No |
| `GET` | `/api/auth/profile` | Get user profile | Yes |
| `POST` | `/api/auth/logout` | Logout user | Yes |
| `POST` | `/api/auth/refresh` | Refresh access token | No (uses refresh token) |

---

For detailed documentation, see: `GITHUB_OAUTH_API_DOCUMENTATION.md`

