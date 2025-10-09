# 🚀 Cyberix Security Scanner - API Endpoints Quick Reference

## Base URL: `http://localhost:9000`

---

## 📋 **USER MANAGEMENT**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/users` | Get all users (with pagination & filters) |
| `GET` | `/api/users/:id` | Get user by ID |
| `PUT` | `/api/users/:id` | Update user details |
| `PUT` | `/api/users/:id/status` | Update user status |
| `DELETE` | `/api/users/:id` | Delete user |
| `GET` | `/api/users/stats/overview` | Get user statistics |

**Query Params for `/api/users`:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10)
- `search` (optional): Search term
- `status` (optional): Filter by status

---

## 🔧 **SECURITY TOOLS**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/security-tools` | Get all security tools |
| `GET` | `/api/security-tools/categories` | Get tool categories |
| `PUT` | `/api/security-tools/:id/toggle` | Toggle tool status |
| `POST` | `/api/security-tools/deploy-updates` | Deploy tool updates |

**Query Params for `/api/security-tools`:**
- `category` (optional): Filter by category
- `search` (optional): Search term
- `status` (optional): Filter by status

---

## 💼 **SERVICE PLANS**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/plans` | Get all service plans |
| `POST` | `/api/plans` | Create new service plan |
| `GET` | `/api/plans/:id` | Get plan by ID |
| `PUT` | `/api/plans/:id` | Update service plan |
| `DELETE` | `/api/plans/:id` | Delete service plan |

**Query Params for `/api/plans`:**
- `search` (optional): Search term
- `status` (optional): Filter by status
- `isPopular` (optional): Filter by popularity

---

## 📢 **POST ADS**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/ads` | Get all ads |
| `GET` | `/api/ads/stats` | Get ad statistics |
| `POST` | `/api/ads` | Create new ad |
| `PUT` | `/api/ads/:id` | Update ad |
| `PUT` | `/api/ads/:id/toggle` | Toggle ad status |
| `DELETE` | `/api/ads/:id` | Delete ad |

**Query Params for `/api/ads`:**
- `search` (optional): Search term
- `status` (optional): Filter by status
- `priority` (optional): Filter by priority

---

## 🔔 **PUSH NOTIFICATIONS**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/notifications` | Get all notifications |
| `GET` | `/api/notifications/stats` | Get notification statistics |
| `POST` | `/api/notifications` | Create new notification |
| `POST` | `/api/notifications/:id/send` | Send notification |
| `DELETE` | `/api/notifications/:id` | Delete notification |

**Query Params for `/api/notifications`:**
- `search` (optional): Search term
- `status` (optional): Filter by status
- `type` (optional): Filter by type
- `targetAudience` (optional): Filter by target audience

---

## 🔐 **AUTHENTICATION**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/register` | Register new user |
| `POST` | `/api/auth/login` | User login |
| `POST` | `/api/auth/logout` | User logout |
| `GET` | `/api/auth/profile` | Get user profile |
| `POST` | `/api/auth/refresh` | Refresh access token |

---

## 📊 **DASHBOARD**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard/stats` | Get dashboard statistics |
| `GET` | `/api/dashboard/activity` | Get recent activity |
| `GET` | `/api/dashboard/revenue-chart` | Get revenue chart data |
| `GET` | `/api/dashboard/users-chart` | Get users chart data |

---

## 👨‍💼 **ADMIN**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/admin/users` | Get all users (admin view) |
| `GET` | `/api/admin/users/:id` | Get user by ID (admin view) |
| `PUT` | `/api/admin/users/:id/status` | Update user status (admin) |
| `GET` | `/api/admin/dashboard-stats` | Get admin dashboard statistics |

---

## 🏥 **SYSTEM**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api` | API information |

---

## 📝 **Request/Response Examples**

### User Registration
```bash
POST /api/register
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe", 
  "email": "john.doe@company.com",
  "phone": "+1-555-123-4567",
  "subscriptionType": "FREE"
}
```

### User Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "john.doe@company.com",
  "password": "generated-password"
}
```

### Get Users with Filters
```bash
GET /api/users?page=1&limit=10&search=john&status=Active
```

### Create Service Plan
```bash
POST /api/plans
Content-Type: application/json

{
  "name": "Premium Security Suite",
  "price": 999,
  "description": "Advanced security solution",
  "features": ["Advanced scan", "Real-time monitoring"],
  "deliveryDays": 3,
  "isPopular": true,
  "isActive": true
}
```

### Create Notification
```bash
POST /api/notifications
Content-Type: application/json

{
  "title": "System Maintenance Notice",
  "message": "Scheduled maintenance tonight 2-4 AM EST",
  "type": "warning",
  "targetAudience": "all",
  "scheduledAt": "2024-01-20 18:00:00"
}
```

---

## 🔑 **Authentication Headers**
For protected endpoints, include:
```
Authorization: Bearer <your-jwt-token>
```

---

## 📊 **Response Format**
All endpoints return consistent JSON responses:

**Success:**
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation successful"
}
```

**Error:**
```json
{
  "success": false,
  "error": {
    "message": "Error description",
    "statusCode": 400
  }
}
```

---

## 🧪 **Testing**
Run the test script to verify all endpoints:
```bash
node test-apis.js
```

---

## 📚 **Full Documentation**
See `API_DOCUMENTATION.md` for complete details with all request/response examples.
