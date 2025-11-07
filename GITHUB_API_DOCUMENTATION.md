# GitHub OAuth API Documentation

This API provides GitHub OAuth authentication and repository access for Electron.js applications.

## Setup

### 1. Environment Variables

Add the following to your `.env` file:

```env
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_CALLBACK_URL=http://localhost:4005/api/github/callback
```

### 2. GitHub OAuth App Setup

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: Your app name
   - **Homepage URL**: Your app URL
   - **Authorization callback URL**: `http://localhost:4005/api/github/callback` (or your production URL)
4. Click "Register application"
5. Copy the **Client ID** and **Client Secret** to your `.env` file

### 3. Install Dependencies

```bash
npm install passport-github2 @types/passport-github2
```

## API Endpoints

### 1. Initiate GitHub OAuth

**GET** `/api/github/auth`

Initiates the GitHub OAuth flow. Redirects user to GitHub for authentication.

**Query Parameters:**
- `redirect` (optional): URL to redirect to after authentication (for Electron app)

**Example:**
```
GET /api/github/auth?redirect=myapp://github-callback
```

### 2. GitHub OAuth Callback

**GET** `/api/github/callback`

Handles the GitHub OAuth callback. Returns access token and user info.

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "gho_xxxxxxxxxxxx",
    "user": {
      "id": 123456,
      "login": "username",
      "name": "User Name",
      "email": "user@example.com",
      "avatar": "https://avatars.githubusercontent.com/u/123456",
      "bio": "User bio",
      "company": "Company Name",
      "location": "Location",
      "publicRepos": 10,
      "followers": 50,
      "following": 30
    }
  },
  "message": "GitHub authentication successful"
}
```

**If redirect URL provided:**
Redirects to: `{redirectUrl}?token={accessToken}&user={userInfo}`

### 3. Get User's Organizations

**GET** `/api/github/organizations`

Get all organizations the authenticated user belongs to.

**Headers:**
- `Authorization: Bearer {github_access_token}` OR
- `X-GitHub-Token: {github_access_token}` OR
- `token` query parameter

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 123456,
      "login": "org-name",
      "name": "Organization Name",
      "avatar": "https://avatars.githubusercontent.com/u/123456",
      "description": "Org description",
      "type": "Organization"
    }
  ],
  "message": "Organizations retrieved successfully"
}
```

### 4. Get Organization Repositories

**GET** `/api/github/repos/:org`

Get all repositories for a specific organization.

**Path Parameters:**
- `org`: Organization name

**Headers:**
- `Authorization: Bearer {github_access_token}` OR
- `X-GitHub-Token: {github_access_token}` OR
- `token` query parameter

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 123456,
      "name": "repo-name",
      "fullName": "org-name/repo-name",
      "description": "Repository description",
      "private": false,
      "language": "TypeScript",
      "stars": 100,
      "forks": 20,
      "defaultBranch": "main",
      "updatedAt": "2025-11-07T10:00:00Z",
      "url": "https://github.com/org-name/repo-name",
      "cloneUrl": "https://github.com/org-name/repo-name.git",
      "sshUrl": "git@github.com:org-name/repo-name.git"
    }
  ],
  "message": "Repositories retrieved successfully"
}
```

### 5. Get Repository Contents (All Code)

**GET** `/api/github/repo/:owner/:repo/contents`

Get all files and directories from a repository recursively.

**Path Parameters:**
- `owner`: Repository owner (username or org name)
- `repo`: Repository name

**Query Parameters:**
- `path` (optional): Path to start from (default: root)
- `branch` (optional): Branch name (default: default branch)

**Headers:**
- `Authorization: Bearer {github_access_token}` OR
- `X-GitHub-Token: {github_access_token}` OR
- `token` query parameter

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "type": "file",
      "path": "src/index.ts",
      "name": "index.ts",
      "size": 1024,
      "sha": "abc123...",
      "content": "base64_encoded_content",
      "encoding": "base64",
      "downloadUrl": "https://raw.githubusercontent.com/...",
      "url": "https://github.com/..."
    },
    {
      "type": "directory",
      "path": "src/components",
      "name": "components",
      "contents": [
        {
          "type": "file",
          "path": "src/components/Button.tsx",
          "name": "Button.tsx",
          "content": "...",
          ...
        }
      ]
    }
  ],
  "message": "Repository contents retrieved successfully"
}
```

### 6. Get Repository Branches

**GET** `/api/github/repo/:owner/:repo/branches`

Get all branches for a repository.

**Path Parameters:**
- `owner`: Repository owner
- `repo`: Repository name

**Headers:**
- `Authorization: Bearer {github_access_token}` OR
- `X-GitHub-Token: {github_access_token}` OR
- `token` query parameter

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "name": "main",
      "sha": "abc123...",
      "protected": false
    },
    {
      "name": "develop",
      "sha": "def456...",
      "protected": false
    }
  ],
  "message": "Branches retrieved successfully"
}
```

### 7. Get User Info

**GET** `/api/github/user`

Get authenticated user's GitHub profile information.

**Headers:**
- `Authorization: Bearer {github_access_token}` OR
- `X-GitHub-Token: {github_access_token}` OR
- `token` query parameter

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 123456,
    "login": "username",
    "name": "User Name",
    "email": "user@example.com",
    "avatar": "https://avatars.githubusercontent.com/u/123456",
    "bio": "User bio",
    "company": "Company Name",
    "location": "Location",
    "publicRepos": 10,
    "followers": 50,
    "following": 30
  },
  "message": "User info retrieved successfully"
}
```

## Electron.js Integration Flow

### Step 1: Initiate OAuth

```javascript
// In your Electron app
const authUrl = 'http://localhost:4005/api/github/auth?redirect=myapp://github-callback';
// Open in browser or webview
```

### Step 2: Handle Callback

```javascript
// Register custom protocol handler
app.setAsDefaultProtocolClient('myapp');

// Handle callback
app.on('open-url', (event, url) => {
  const params = new URL(url).searchParams;
  const token = params.get('token');
  const user = JSON.parse(decodeURIComponent(params.get('user')));
  
  // Store token securely
  // Use token for subsequent API calls
});
```

### Step 3: Use Token for API Calls

```javascript
// Get organizations
const orgs = await fetch('http://localhost:4005/api/github/organizations', {
  headers: {
    'X-GitHub-Token': token
  }
});

// Get repositories
const repos = await fetch(`http://localhost:4005/api/github/repos/${orgName}`, {
  headers: {
    'X-GitHub-Token': token
  }
});

// Get repository contents
const contents = await fetch(`http://localhost:4005/api/github/repo/${owner}/${repo}/contents`, {
  headers: {
    'X-GitHub-Token': token
  }
});
```

## Error Responses

All endpoints return errors in the following format:

```json
{
  "success": false,
  "error": {
    "message": "Error message",
    "statusCode": 400
  }
}
```

## Notes

- All endpoints except `/auth` and `/callback` require authentication
- The access token should be stored securely in your Electron app
- File contents are returned as base64-encoded strings
- Large repositories may take time to fetch all contents recursively
- GitHub API rate limits apply (5000 requests/hour for authenticated requests)

