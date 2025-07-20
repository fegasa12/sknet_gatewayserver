# Private API Proxy Guide

This guide explains how to make calls to your private API through the gateway server using the new proxy endpoint.

## 🚀 Overview

The gateway now includes a general-purpose proxy endpoint that allows authenticated users to make calls to the private API. This provides:

- ✅ **Authentication**: All requests are authenticated via JWT
- ✅ **Audit Logging**: All API calls are logged for security
- ✅ **Error Handling**: Proper error responses and logging
- ✅ **mTLS Support**: Uses mutual TLS certificates for private API communication
- ✅ **User Context**: Automatically adds user information to requests

## 🔗 Proxy Endpoint

### **Base URL**
```
/api/proxy/*
```

### **Authentication Required**
All proxy requests require a valid JWT token in the Authorization header:
```
Authorization: Bearer your-jwt-token
```

## 📡 Making API Calls

### **GET Requests**
```bash
# Get user data from private API
curl -X GET "https://your-gateway.com/api/proxy/users/123" \
  -H "Authorization: Bearer your-jwt-token"

# With query parameters
curl -X GET "https://your-gateway.com/api/proxy/users?role=admin&status=active" \
  -H "Authorization: Bearer your-jwt-token"
```

### **POST Requests**
```bash
# Create a new resource
curl -X POST "https://your-gateway.com/api/proxy/users" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "role": "user"
  }'
```

### **PUT Requests**
```bash
# Update a resource
curl -X PUT "https://your-gateway.com/api/proxy/users/123" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Smith",
    "email": "john.smith@example.com"
  }'
```

### **DELETE Requests**
```bash
# Delete a resource
curl -X DELETE "https://your-gateway.com/api/proxy/users/123" \
  -H "Authorization: Bearer your-jwt-token"
```

## 🔐 Headers Added Automatically

The gateway automatically adds these headers to your private API requests:

| Header | Value | Description |
|--------|-------|-------------|
| `X-Gateway-Token` | Your gateway secret | Authenticates the gateway to the private API |
| `X-User-ID` | User ID | The authenticated user's ID |
| `X-Username` | Username | The authenticated user's username |
| `X-Request-ID` | UUID | Unique request identifier for tracking |
| `Content-Type` | From original request | Preserves content type |

## 📊 Response Format

### **Successful Response**
```json
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "createdAt": "2024-01-01T10:00:00Z"
}
```

### **Error Response**
```json
{
  "error": "Private API error",
  "message": "User not found",
  "status": 404
}
```

## 🔍 Audit Logging

All proxy requests are automatically logged in the `security_events` table:

### **Successful Calls**
```sql
SELECT * FROM security_events 
WHERE event_type = 'private_api_call' 
ORDER BY timestamp DESC;
```

### **Failed Calls**
```sql
SELECT * FROM security_events 
WHERE event_type = 'private_api_error' 
ORDER BY timestamp DESC;
```

### **Log Data Structure**
```json
{
  "event_type": "private_api_call",
  "user_id": 1,
  "data": {
    "endpoint": "/users/123",
    "method": "GET",
    "statusCode": 200,
    "userAgent": "curl/7.68.0"
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 🛠️ Complete Examples

### **1. User Management**
```bash
# Get all users
curl -X GET "https://your-gateway.com/api/proxy/users" \
  -H "Authorization: Bearer your-jwt-token"

# Get specific user
curl -X GET "https://your-gateway.com/api/proxy/users/123" \
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

### **2. Document Management**
```bash
# Get document list
curl -X GET "https://your-gateway.com/api/proxy/documents" \
  -H "Authorization: Bearer your-jwt-token"

# Get document details
curl -X GET "https://your-gateway.com/api/proxy/documents/456" \
  -H "Authorization: Bearer your-jwt-token"

# Upload document
curl -X POST "https://your-gateway.com/api/proxy/documents" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@document.pdf" \
  -F "title=My Document"
```

### **3. Analytics & Reports**
```bash
# Get analytics data
curl -X GET "https://your-gateway.com/api/proxy/analytics?period=monthly" \
  -H "Authorization: Bearer your-jwt-token"

# Generate report
curl -X POST "https://your-gateway.com/api/proxy/reports" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"type": "user_activity", "dateRange": {"start": "2024-01-01", "end": "2024-01-31"}}'
```

## 🔧 JavaScript/Node.js Examples

### **Using Fetch API**
```javascript
// Get user data
async function getUser(userId, token) {
  const response = await fetch(`https://your-gateway.com/api/proxy/users/${userId}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
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

// Configure axios instance
const apiClient = axios.create({
  baseURL: 'https://your-gateway.com/api/proxy',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});

// Get users
const getUsers = async () => {
  const response = await apiClient.get('/users');
  return response.data;
};

// Create user
const createUser = async (userData) => {
  const response = await apiClient.post('/users', userData);
  return response.data;
};
```

## 🚨 Error Handling

### **Common Error Responses**

#### **401 Unauthorized**
```json
{
  "error": "No token provided"
}
```

#### **403 Forbidden**
```json
{
  "error": "Invalid token"
}
```

#### **503 Service Unavailable**
```json
{
  "error": "Private API unavailable",
  "message": "The private API service is not available"
}
```

#### **500 Internal Server Error**
```json
{
  "error": "Proxy error",
  "message": "Failed to proxy request to private API"
}
```

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

## 🔒 Security Considerations

### **Authentication**
- All requests require valid JWT tokens
- Tokens are validated on every request
- Expired tokens are rejected

### **Audit Trail**
- All API calls are logged with user context
- Failed requests are logged separately
- Request metadata is preserved

### **Rate Limiting**
- Proxy requests are subject to the same rate limits
- 100 requests per 15 minutes per IP
- Additional limits may apply to specific endpoints

### **mTLS Security**
- Gateway uses mutual TLS for private API communication
- Certificates are validated
- Secure communication channel

## 📈 Monitoring & Debugging

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

### **Check Failed API Calls**
```sql
SELECT 
  se.timestamp,
  se.data->>'endpoint' as endpoint,
  se.data->>'method' as method,
  se.data->>'error' as error,
  u.username
FROM security_events se
JOIN users u ON se.user_id = u.id
WHERE se.event_type = 'private_api_error'
ORDER BY se.timestamp DESC
LIMIT 10;
```

## 🎯 Best Practices

1. **Always handle errors**: Check response status and handle errors appropriately
2. **Use appropriate HTTP methods**: GET for retrieval, POST for creation, PUT for updates, DELETE for removal
3. **Include proper headers**: Set Content-Type for requests with bodies
4. **Monitor usage**: Check audit logs regularly for unusual activity
5. **Token management**: Refresh tokens before they expire
6. **Rate limiting**: Be aware of rate limits and implement retry logic if needed

## 🔄 Migration from Direct API Calls

If you're currently calling the private API directly, here's how to migrate:

### **Before (Direct API)**
```javascript
// Direct API call
const response = await fetch('https://private-api.internal/users/123', {
  headers: {
    'X-Gateway-Token': 'your-secret'
  }
});
```

### **After (Through Gateway)**
```javascript
// Through gateway proxy
const response = await fetch('https://your-gateway.com/api/proxy/users/123', {
  headers: {
    'Authorization': 'Bearer your-jwt-token'
  }
});
```

The gateway automatically adds the `X-Gateway-Token` and user context headers, so you only need to provide authentication.

Your private API proxy is now ready for secure, authenticated access with comprehensive audit logging! 🎉 