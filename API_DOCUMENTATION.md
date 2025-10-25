# Cyberix Security Scanner - Complete API Documentation

## Base URL
```
http://localhost:9000
```

## Authentication
All endpoints (except registration and health check) require authentication via Bearer token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

---

## 1. USER MANAGEMENT APIs

### 1.1 Get All Users
**GET** `/api/users`

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10)
- `search` (optional): Search term for name, email, or company
- `status` (optional): Filter by status (Active, Inactive, Trial, Expired)

**Example Request:**
```bash
GET /api/users?page=1&limit=10&search=john&status=Active
```

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": 1,
        "name": "John Smith",
        "email": "john.smith@techcorp.com",
        "company": "TechCorp Solutions",
        "plan": "Professional",
        "status": "Active",
        "lastScan": "2 hours ago",
        "scansCompleted": 45,
        "avatar": "/images/user/user-17.jpg",
        "phone": "+1 (555) 123-4567",
        "location": "New York, USA",
        "bio": "IT Security Manager at TechCorp"
      }
    ],
    "total": 1,
    "page": 1,
    "limit": 10,
    "totalPages": 1
  },
  "message": "Users retrieved successfully"
}
```

### 1.2 Get User by ID
**GET** `/api/users/:id`

**Example Request:**
```bash
GET /api/users/1
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john.doe@example.com",
    "company": "Example Corp",
    "plan": "Professional",
    "status": "Active",
    "lastScan": "2 hours ago",
    "scansCompleted": 45,
    "avatar": "/images/user/user-17.jpg",
    "phone": "+1 (555) 123-4567",
    "location": "New York, USA",
    "bio": "IT Security Manager at Example Corp"
  },
  "message": "User retrieved successfully"
}
```

### 1.3 Update User
**PUT** `/api/users/:id`

**Request Body:**
```json
{
  "name": "John Updated",
  "email": "john.updated@example.com",
  "company": "Updated Corp",
  "plan": "Enterprise",
  "status": "Active"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "John Updated",
    "email": "john.updated@example.com",
    "company": "Updated Corp",
    "plan": "Enterprise",
    "status": "Active"
  },
  "message": "User updated successfully"
}
```

### 1.4 Update User Status
**PUT** `/api/users/:id/status`

**Request Body:**
```json
{
  "status": "Inactive"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "status": "Inactive"
  },
  "message": "User status updated successfully"
}
```

### 1.5 Delete User
**DELETE** `/api/users/:id`

**Response:**
```json
{
  "success": true,
  "message": "User with ID 1 deleted successfully"
}
```

### 1.6 Get User Statistics
**GET** `/api/users/stats/overview`

**Response:**
```json
{
  "success": true,
  "data": {
    "totalUsers": 2847,
    "activeUsers": 1923,
    "trialUsers": 456,
    "premiumUsers": 468,
    "newUsersToday": 15,
    "churnRate": 2.1
  },
  "message": "User statistics retrieved successfully"
}
```

---

## 2. SECURITY TOOLS APIs

### 2.1 Get All Security Tools
**GET** `/api/security-tools`

**Query Parameters:**
- `category` (optional): Filter by category (scanning, monitoring, analysis, reporting)
- `search` (optional): Search term for name or description
- `status` (optional): Filter by status (active, inactive)

**Example Request:**
```bash
GET /api/security-tools?category=scanning&search=port&status=active
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "port-scanner",
      "name": "Port Scanner",
      "description": "Comprehensive port scanning to identify open ports and services",
      "category": "scanning",
      "isEnabled": true,
      "features": [
        "TCP/UDP scanning",
        "Service detection",
        "Vulnerability mapping",
        "Custom port ranges"
      ],
      "status": "active",
      "lastUpdated": "2 hours ago"
    }
  ],
  "message": "Security tools retrieved successfully"
}
```

### 2.2 Get Tool Categories
**GET** `/api/security-tools/categories`

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "scanning",
      "name": "Scanning Tools",
      "description": "Core scanning modules for comprehensive security analysis"
    },
    {
      "id": "monitoring",
      "name": "Monitoring Tools",
      "description": "Real-time monitoring and alerting systems"
    }
  ],
  "message": "Tool categories retrieved successfully"
}
```

### 2.3 Toggle Tool Status
**PUT** `/api/security-tools/:id/toggle`

**Response:**
```json
{
  "success": true,
  "message": "Tool status toggled successfully"
}
```

### 2.4 Deploy Updates
**POST** `/api/security-tools/deploy-updates`

**Response:**
```json
{
  "success": true,
  "message": "Updates deployed successfully"
}
```

---

## 3. SERVICE PLANS APIs

### 3.1 Get All Service Plans
**GET** `/api/plans`

**Query Parameters:**
- `search` (optional): Search term for name or description
- `status` (optional): Filter by status (active, inactive)
- `isPopular` (optional): Filter by popularity (true, false)

**Example Request:**
```bash
GET /api/plans?search=security&status=active&isPopular=true
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "1",
      "name": "Basic Security Scan",
      "price": 299,
      "description": "Comprehensive security assessment to identify vulnerabilities and protect your website from potential threats.",
      "features": [
        "Basic vulnerability scan",
        "SSL certificate check",
        "Security headers analysis",
        "Basic penetration testing",
        "Detailed security report"
      ],
      "deliveryDays": 2,
      "isPopular": false,
      "isActive": true,
      "createdAt": "2024-01-01",
      "updatedAt": "2024-01-01"
    }
  ],
  "message": "Plans retrieved successfully"
}
```

### 3.2 Create Service Plan
**POST** `/api/plans`

**Request Body:**
```json
{
  "name": "Premium Security Suite",
  "price": 999,
  "description": "Advanced security solution with comprehensive protection",
  "features": [
    "Advanced vulnerability scan",
    "Real-time monitoring",
    "Priority support"
  ],
  "deliveryDays": 3,
  "isPopular": true,
  "isActive": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "4",
    "name": "Premium Security Suite",
    "price": 999,
    "description": "Advanced security solution with comprehensive protection",
    "features": [
      "Advanced vulnerability scan",
      "Real-time monitoring",
      "Priority support"
    ],
    "deliveryDays": 3,
    "isPopular": true,
    "isActive": true
  },
  "message": "Plan created successfully"
}
```

### 3.3 Get Plan by ID
**GET** `/api/plans/:id`

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "1",
    "name": "Basic Security Scan",
    "price": 299,
    "description": "Comprehensive security assessment",
    "features": ["Basic vulnerability scan", "SSL certificate check"],
    "deliveryDays": 2,
    "isPopular": false,
    "isActive": true
  },
  "message": "Plan retrieved successfully"
}
```

### 3.4 Update Plan
**PUT** `/api/plans/:id`

**Request Body:**
```json
{
  "name": "Updated Basic Security Scan",
  "price": 399,
  "description": "Updated comprehensive security assessment",
  "features": ["Updated vulnerability scan", "Enhanced SSL check"],
  "deliveryDays": 1,
  "isPopular": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "1",
    "name": "Updated Basic Security Scan",
    "price": 399,
    "description": "Updated comprehensive security assessment",
    "features": ["Updated vulnerability scan", "Enhanced SSL check"],
    "deliveryDays": 1,
    "isPopular": true
  },
  "message": "Plan updated successfully"
}
```

### 3.5 Delete Plan
**DELETE** `/api/plans/:id`

**Response:**
```json
{
  "success": true,
  "message": "Plan deleted successfully"
}
```

---

## 4. POST ADS APIs

### 4.1 Get All Ads
**GET** `/api/ads`

**Query Parameters:**
- `search` (optional): Search term for title or content
- `status` (optional): Filter by status (active, inactive)
- `priority` (optional): Filter by priority (high, medium, low)

**Example Request:**
```bash
GET /api/ads?search=security&status=active&priority=high
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "1",
      "title": "50% OFF - Professional Security Scanner",
      "content": "Limited time offer! Get 50% discount on our Professional Security Scanner plan. Secure your website today!",
      "link": "https://cyberix.com/purchase?discount=50off",
      "isActive": true,
      "priority": "high",
      "startDate": "2024-01-15",
      "endDate": "2024-02-15",
      "createdAt": "2024-01-10",
      "updatedAt": "2024-01-12",
      "clicks": 1247,
      "impressions": 15680
    }
  ],
  "message": "Ads retrieved successfully"
}
```

### 4.2 Get Ad Statistics
**GET** `/api/ads/stats`

**Response:**
```json
{
  "success": true,
  "data": {
    "totalAds": 15,
    "activeAds": 8,
    "totalClicks": 12547,
    "totalImpressions": 156780,
    "clickThroughRate": 8.0,
    "topPerformingAd": "50% OFF - Professional Security Scanner"
  },
  "message": "Ad statistics retrieved successfully"
}
```

### 4.3 Create Ad
**POST** `/api/ads`

**Request Body:**
```json
{
  "title": "New Security Update Available",
  "content": "Check out our latest security features and updates",
  "link": "https://cyberix.com/updates",
  "priority": "medium",
  "startDate": "2024-01-20",
  "endDate": "2024-02-20",
  "isActive": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "4",
    "title": "New Security Update Available",
    "content": "Check out our latest security features and updates",
    "link": "https://cyberix.com/updates",
    "priority": "medium",
    "startDate": "2024-01-20",
    "endDate": "2024-02-20",
    "isActive": true,
    "clicks": 0,
    "impressions": 0
  },
  "message": "Ad created successfully"
}
```

### 4.4 Update Ad
**PUT** `/api/ads/:id`

**Request Body:**
```json
{
  "title": "Updated Security Update",
  "content": "Updated content for the security update",
  "priority": "high",
  "isActive": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "1",
    "title": "Updated Security Update",
    "content": "Updated content for the security update",
    "priority": "high",
    "isActive": true
  },
  "message": "Ad updated successfully"
}
```

### 4.5 Toggle Ad Status
**PUT** `/api/ads/:id/toggle`

**Response:**
```json
{
  "success": true,
  "message": "Ad status toggled successfully"
}
```

### 4.6 Delete Ad
**DELETE** `/api/ads/:id`

**Response:**
```json
{
  "success": true,
  "message": "Ad deleted successfully"
}
```

---

## 5. PUSH NOTIFICATIONS APIs

### 5.1 Get All Notifications
**GET** `/api/notifications`

**Query Parameters:**
- `search` (optional): Search term for title or message
- `status` (optional): Filter by status (sent, scheduled, failed)
- `type` (optional): Filter by type (info, warning, success, error)
- `targetAudience` (optional): Filter by target audience (all, premium, trial, specific)

**Example Request:**
```bash
GET /api/notifications?search=security&status=sent&type=info&targetAudience=all
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "1",
      "title": "New Security Update Available",
      "message": "We've released a new security scanner update with enhanced vulnerability detection. Update now to stay protected!",
      "type": "info",
      "targetAudience": "all",
      "sentAt": "2024-01-15 10:30:00",
      "status": "sent",
      "deliveryStats": {
        "sent": 2847,
        "delivered": 2756,
        "opened": 1923,
        "clicked": 456
      },
      "createdAt": "2024-01-15 10:00:00",
      "createdBy": "Admin"
    }
  ],
  "message": "Notifications retrieved successfully"
}
```

### 5.2 Get Notification Statistics
**GET** `/api/notifications/stats`

**Response:**
```json
{
  "success": true,
  "data": {
    "totalNotifications": 45,
    "sentToday": 3,
    "scheduled": 2,
    "totalRecipients": 2847,
    "averageOpenRate": 67.5,
    "averageClickRate": 16.8
  },
  "message": "Notification statistics retrieved successfully"
}
```

### 5.3 Create Notification
**POST** `/api/notifications`

**Request Body:**
```json
{
  "title": "System Maintenance Notice",
  "message": "We will be performing scheduled maintenance on our servers tonight from 2 AM to 4 AM EST. Some services may be temporarily unavailable.",
  "type": "warning",
  "targetAudience": "all",
  "scheduledAt": "2024-01-20 18:00:00"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "4",
    "title": "System Maintenance Notice",
    "message": "We will be performing scheduled maintenance on our servers tonight from 2 AM to 4 AM EST. Some services may be temporarily unavailable.",
    "type": "warning",
    "targetAudience": "all",
    "scheduledAt": "2024-01-20 18:00:00",
    "status": "scheduled",
    "createdAt": "2024-01-15 10:00:00",
    "createdBy": "Admin"
  },
  "message": "Notification created successfully"
}
```

### 5.4 Send Notification
**POST** `/api/notifications/:id/send`

**Response:**
```json
{
  "success": true,
  "message": "Notification sent successfully"
}
```

### 5.5 Delete Notification
**DELETE** `/api/notifications/:id`

**Response:**
```json
{
  "success": true,
  "message": "Notification deleted successfully"
}
```

---

## 6. AUTHENTICATION APIs

### 6.1 User Registration
**POST** `/api/register`

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@company.com",
  "phone": "+1-555-123-4567",
  "subscriptionType": "FREE"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": 1,
      "firstName": "John",
      "lastName": "Doe",
      "email": "john.doe@company.com",
      "phone": "+1-555-123-4567",
      "subscriptionType": "FREE",
      "status": "active"
    },
    "message": "User registered successfully. Login credentials sent to email."
  },
  "message": "Registration successful"
}
```

### 6.2 User Login
**POST** `/api/auth/login`

**Request Body:**
```json
{
  "email": "john.doe@company.com",
  "password": "generated-password"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": 1,
      "firstName": "John",
      "lastName": "Doe",
      "email": "john.doe@company.com",
      "subscriptionType": "FREE"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "message": "Login successful"
}
```

### 6.3 User Logout
**POST** `/api/auth/logout`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

### 6.4 Get User Profile
**GET** `/api/auth/profile`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "firstName": "John",
    "lastName": "Doe",
    "email": "john.doe@company.com",
    "subscriptionType": "FREE",
    "status": "active"
  },
  "message": "Profile retrieved successfully"
}
```

### 6.5 Refresh Token
**POST** `/api/auth/refresh`

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "message": "Token refreshed successfully"
}
```

---

## 7. DASHBOARD APIs

### 7.1 Get Dashboard Statistics
**GET** `/api/dashboard/stats`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "totalUsers": 2847,
    "activeScans": 156,
    "totalRevenue": 125000,
    "securityAlerts": 23,
    "systemHealth": 98.5,
    "uptime": "99.9%"
  },
  "message": "Dashboard statistics retrieved successfully"
}
```

### 7.2 Get Recent Activity
**GET** `/api/dashboard/activity`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "1",
      "type": "scan_completed",
      "message": "Security scan completed for example.com",
      "timestamp": "2024-01-15 10:30:00",
      "severity": "info"
    },
    {
      "id": "2",
      "type": "user_registered",
      "message": "New user registered: john.doe@company.com",
      "timestamp": "2024-01-15 09:15:00",
      "severity": "success"
    }
  ],
  "message": "Recent activity retrieved successfully"
}
```

### 7.3 Get Revenue Chart Data
**GET** `/api/dashboard/revenue-chart`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "labels": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
    "datasets": [
      {
        "label": "Revenue",
        "data": [12000, 15000, 18000, 22000, 25000, 28000],
        "borderColor": "#3b82f6",
        "backgroundColor": "rgba(59, 130, 246, 0.1)"
      }
    ]
  },
  "message": "Revenue chart data retrieved successfully"
}
```

### 7.4 Get Users Chart Data
**GET** `/api/dashboard/users-chart`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "labels": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
    "datasets": [
      {
        "label": "New Users",
        "data": [45, 52, 38, 67, 89, 95],
        "borderColor": "#10b981",
        "backgroundColor": "rgba(16, 185, 129, 0.1)"
      },
      {
        "label": "Active Users",
        "data": [120, 135, 142, 158, 167, 175],
        "borderColor": "#f59e0b",
        "backgroundColor": "rgba(245, 158, 11, 0.1)"
      }
    ]
  },
  "message": "Users chart data retrieved successfully"
}
```

---

## 8. ADMIN APIs

### 8.1 Get All Users (Admin)
**GET** `/api/admin/users`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10)
- `search` (optional): Search term
- `status` (optional): Filter by status

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": 1,
        "name": "John Smith",
        "email": "john.smith@techcorp.com",
        "company": "TechCorp Solutions",
        "plan": "Professional",
        "status": "Active",
        "lastScan": "2 hours ago",
        "scansCompleted": 45
      }
    ],
    "total": 1,
    "page": 1,
    "limit": 10,
    "totalPages": 1
  },
  "message": "Users retrieved successfully"
}
```

### 8.2 Get User by ID (Admin)
**GET** `/api/admin/users/:id`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john.doe@example.com",
    "company": "Example Corp",
    "plan": "Professional",
    "status": "Active",
    "lastScan": "2 hours ago",
    "scansCompleted": 45
  },
  "message": "User retrieved successfully"
}
```

### 8.3 Update User Status (Admin)
**PUT** `/api/admin/users/:id/status`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Request Body:**
```json
{
  "status": "Inactive"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "status": "Inactive"
  },
  "message": "User status updated successfully"
}
```

### 8.4 Get Admin Dashboard Statistics
**GET** `/api/admin/dashboard-stats`

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "totalUsers": 2847,
    "activeUsers": 1923,
    "totalRevenue": 125000,
    "securityAlerts": 23,
    "systemHealth": 98.5,
    "uptime": "99.9%"
  },
  "message": "Admin dashboard statistics retrieved successfully"
}
```

---

## 9. HEALTH CHECK

### 9.1 Health Check
**GET** `/health`

**Response:**
```json
{
  "status": "OK",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": 3600,
  "environment": "development"
}
```

---

## 10. API INFO

### 10.1 API Information
**GET** `/api`

**Response:**
```json
{
  "success": true,
  "data": {
    "name": "Cyberix Security Scanner API",
    "version": "1.0.0",
    "description": "Comprehensive API for cybersecurity scanner administration",
    "endpoints": {
      "users": "/api/users",
      "security-tools": "/api/security-tools",
      "plans": "/api/plans",
      "ads": "/api/ads",
      "notifications": "/api/notifications",
      "auth": "/api/auth",
      "dashboard": "/api/dashboard",
      "admin": "/api/admin"
    }
  },
  "message": "API information retrieved successfully"
}
```

---

## Error Responses

All endpoints return consistent error responses:

```json
{
  "success": false,
  "error": {
    "message": "Error description",
    "statusCode": 400
  }
}
```

**Common HTTP Status Codes:**
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

---

## Rate Limiting

- **Rate Limit**: 100 requests per 15 minutes per IP
- **Headers**: Rate limit information is included in response headers
  - `X-RateLimit-Limit`: Maximum requests allowed
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Time when the rate limit resets

---

## CORS Configuration

- **Allowed Origins**: `http://localhost:3000`, `http://localhost:3001`
- **Allowed Methods**: GET, POST, PUT, DELETE, PATCH, OPTIONS
- **Allowed Headers**: Content-Type, Authorization, X-Requested-With
- **Credentials**: Supported

---

## Testing the APIs

You can test all endpoints using:
- **Postman**: Import the API collection
- **curl**: Use the provided curl examples
- **Frontend**: Integrate with your React/Next.js application

**Base URL for testing**: `http://localhost:9000`
