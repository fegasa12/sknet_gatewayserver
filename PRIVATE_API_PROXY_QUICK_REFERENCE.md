# Private API Proxy - Quick Reference

## 🚀 Overview

Make authenticated calls to your private API through the gateway:

- ✅ **Authentication**: JWT token required
- ✅ **Audit Logging**: All calls logged automatically
- ✅ **mTLS Support**: Secure communication
- ✅ **User Context**: User info added automatically

## 🔗 Proxy Endpoint

```
/api/proxy/*
```

**Authentication**: `Authorization: Bearer your-jwt-token`

## 📡 API Call Examples

### **GET Requests**
```bash
# Get user data
curl -X GET "https://your-gateway.com/api/proxy/users/123" \
  -H "Authorization: Bearer your-jwt-token"

# With query parameters
curl -X GET "https://your-gateway.com/api/proxy/users?role=admin" \
  -H "Authorization: Bearer your-jwt-token"
```

### **POST Requests**
```bash
# Create resource
curl -X POST "https://your-gateway.com/api/proxy/users" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'
```

### **PUT Requests**
```bash
# Update resource
curl -X PUT "https://your-gateway.com/api/proxy/users/123" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "John Smith"}'
```

### **DELETE Requests**
```bash
# Delete resource
curl -X DELETE "https://your-gateway.com/api/proxy/users/123" \
  -H "Authorization: Bearer your-jwt-token"
```

## 🔐 Headers Added Automatically

| Header | Value | Description |
|--------|-------|-------------|
| `X-Gateway-Token` | Gateway secret | Gateway authentication |
| `X-User-ID` | User ID | Authenticated user ID |
| `X-Username` | Username | Authenticated username |
| `X-Request-ID` | UUID | Request tracking |
| `Content-Type` | From request | Preserved content type |

## 📊 Response Examples

### **Success**
```json
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com"
}
```

### **Error**
```json
{
  "error": "Private API error",
  "message": "User not found",
  "status": 404
}
```

## 🔧 JavaScript Examples

### **Using Fetch**
```javascript
// Get user data
async function getUser(userId, token) {
  const response = await fetch(`https://your-gateway.com/api/proxy/users/${userId}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  return await response.json();
}

// Create user
async function createUser(userData, token) {
  const response = await fetch('https://your-gateway.com/api/proxy/users', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(userData)
  });
  return await response.json();
}
```

### **Using Axios**
```javascript
import axios from 'axios';

const apiClient = axios.create({
  baseURL: 'https://your-gateway.com/api/proxy',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});

// Get users
const getUsers = () => apiClient.get('/users');

// Create user
const createUser = (userData) => apiClient.post('/users', userData);
```

## 🛠️ Common Use Cases

### **User Management**
```bash
# Get all users
curl -X GET "https://your-gateway.com/api/proxy/users" \
  -H "Authorization: Bearer your-jwt-token"

# Create user
curl -X POST "https://your-gateway.com/api/proxy/users" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "Jane Doe", "email": "jane@example.com"}'

# Update user
curl -X PUT "https://your-gateway.com/api/proxy/users/123" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "Jane Smith"}'

# Delete user
curl -X DELETE "https://your-gateway.com/api/proxy/users/123" \
  -H "Authorization: Bearer your-jwt-token"
```

### **Document Management**
```bash
# Get documents
curl -X GET "https://your-gateway.com/api/proxy/documents" \
  -H "Authorization: Bearer your-jwt-token"

# Get specific document
curl -X GET "https://your-gateway.com/api/proxy/documents/456" \
  -H "Authorization: Bearer your-jwt-token"

# Upload document
curl -X POST "https://your-gateway.com/api/proxy/documents" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@document.pdf" \
  -F "title=My Document"
```

### **Analytics & Reports**
```bash
# Get analytics
curl -X GET "https://your-gateway.com/api/proxy/analytics?period=monthly" \
  -H "Authorization: Bearer your-jwt-token"

# Generate report
curl -X POST "https://your-gateway.com/api/proxy/reports" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"type": "user_activity", "dateRange": {"start": "2024-01-01", "end": "2024-01-31"}}'
```

## 🔍 Audit Logging

### **Check Recent API Calls**
```sql
SELECT 
  se.timestamp,
  se.data->>'endpoint' as endpoint,
  se.data->>'method' as method,
  se.data->>'statusCode' as status_code,
  u.username
FROM security_events se
JOIN users u ON se.user_id = u.id
WHERE se.event_type = 'private_api_call'
ORDER BY se.timestamp DESC
LIMIT 10;
```

### **Check Failed Calls**
```sql
SELECT 
  se.timestamp,
  se.data->>'endpoint' as endpoint,
  se.data->>'error' as error,
  u.username
FROM security_events se
JOIN users u ON se.user_id = u.id
WHERE se.event_type = 'private_api_error'
ORDER BY se.timestamp DESC
LIMIT 10;
```

## 🚨 Error Handling

### **Common Error Responses**

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `No token provided` | Missing Authorization header |
| 401 | `Invalid token` | Expired or invalid JWT |
| 503 | `Private API unavailable` | Private API service down |
| 500 | `Proxy error` | Gateway internal error |

### **Error Handling in JavaScript**
```javascript
async function makeApiCall(endpoint, token) {
  try {
    const response = await fetch(`https://your-gateway.com/api/proxy${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || `HTTP ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('API call failed:', error.message);
    throw error;
  }
}
```

## 🔒 Security Features

- ✅ **JWT Authentication**: All requests require valid tokens
- ✅ **User Context**: User ID and username added automatically
- ✅ **Audit Trail**: All calls logged with user context
- ✅ **mTLS Security**: Mutual TLS for private API communication
- ✅ **Rate Limiting**: Subject to gateway rate limits
- ✅ **Error Logging**: Failed requests logged separately

## 🔄 Migration from Direct API

### **Before (Direct API)**
```javascript
const response = await fetch('https://private-api.internal/users/123', {
  headers: {
    'X-Gateway-Token': 'your-secret'
  }
});
```

### **After (Through Gateway)**
```javascript
const response = await fetch('https://your-gateway.com/api/proxy/users/123', {
  headers: {
    'Authorization': 'Bearer your-jwt-token'
  }
});
```

## 📖 Full Documentation

See `docs/PRIVATE_API_PROXY_GUIDE.md` for complete guide. 