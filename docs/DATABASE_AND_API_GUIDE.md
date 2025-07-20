# Database Schema & Private API Integration Guide

This guide covers the PostgreSQL database structure, how tables are used, private API expectations, and the complete authentication flow.

## 📊 PostgreSQL Database Schema

### **1. Users Table**
```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(255),
  totp_secret VARCHAR(255),
  biometric_credentials JSONB DEFAULT '[]',
  public_key BYTEA,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP,
  failed_attempts INTEGER DEFAULT 0,
  locked_until TIMESTAMP
);
```

**Purpose**: Stores user authentication and profile data
- **password_hash**: bcrypt hashed passwords (12 rounds by default)
- **totp_secret**: Base32 encoded secret for TOTP 2FA
- **biometric_credentials**: JSON array for mobile biometric auth
- **public_key**: User's public key for encryption
- **failed_attempts**: Tracks login failures (locks after 4 attempts)
- **locked_until**: Account lockout timestamp

### **2. Sessions Table**
```sql
CREATE TABLE sessions (
  id VARCHAR(255) PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  device_fingerprint VARCHAR(255),
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ip_address INET,
  user_agent TEXT
);
```

**Purpose**: Manages active user sessions
- **id**: UUID session token
- **device_fingerprint**: Device identification for security
- **expires_at**: Session expiration timestamp
- **last_activity**: Used for session timeout

### **3. Document Access Logs Table**
```sql
CREATE TABLE document_access_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  document_id VARCHAR(255) NOT NULL,
  action VARCHAR(50) NOT NULL,
  session_id VARCHAR(255),
  ip_address INET,
  user_agent TEXT,
  metadata JSONB,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Purpose**: Audit trail for document access
- **action**: Types: 'view_requested', 'viewed', 'access_denied'
- **metadata**: JSON with additional context (requestId, expiresAt, etc.)

### **4. Security Events Table**
```sql
CREATE TABLE security_events (
  id SERIAL PRIMARY KEY,
  event_type VARCHAR(100) NOT NULL,
  user_id INTEGER REFERENCES users(id),
  session_id VARCHAR(255),
  ip_address INET,
  user_agent TEXT,
  data JSONB,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Purpose**: Security event logging
- **event_type**: Types: 'failed_login', 'successful_login', 'session_created', etc.
- **data**: JSON with event-specific details

### **5. Encrypted Metadata Table**
```sql
CREATE TABLE encrypted_metadata (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  document_id VARCHAR(255) NOT NULL,
  encrypted_data BYTEA NOT NULL,
  last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, document_id)
);
```

**Purpose**: Stores encrypted document metadata per user

## 🔐 Authentication Flow

### **Step 1: Primary Authentication**
```bash
POST /api/auth/primary
Content-Type: application/json

{
  "username": "user1",
  "password": "password123"
}
```

**Response**:
```json
{
  "challengeId": "uuid-challenge-id",
  "otpRequired": true,
  "biometricAvailable": false,
  "message": "Primary authentication successful"
}
```

**Database Operations**:
1. Query users table by username
2. Verify password with bcrypt.compare()
3. Check account lock status
4. Update failed_attempts on failure
5. Store challenge in Redis/session store

### **Step 2: Complete Authentication (MFA)**
```bash
POST /api/auth/complete
Content-Type: application/json

{
  "challengeId": "uuid-challenge-id",
  "secondFactor": {
    "type": "otp",
    "value": "123456"
  },
  "deviceFingerprint": "device-hash"
}
```

**Response**:
```json
{
  "accessToken": "jwt-access-token",
  "refreshToken": "jwt-refresh-token",
  "expiresIn": 900,
  "user": {
    "id": 1,
    "username": "user1",
    "email": "user1@example.com"
  }
}
```

**Database Operations**:
1. Retrieve challenge from Redis/session store
2. Verify TOTP with speakeasy
3. Create session record
4. Update last_login timestamp
5. Generate JWT tokens

## 🔗 Private API Integration

### **Private API Expectations**

The gateway expects a private API with the following endpoints:

#### **1. Document Access Check**
```bash
GET /documents/{documentId}/access
Headers:
  X-Gateway-Token: gateway-secret
  X-User-ID: user-id
  X-Request-ID: request-uuid
```

**Expected Response**:
```json
{
  "hasAccess": true,
  "permissions": ["read", "download"],
  "expiresAt": "2024-01-01T12:00:00Z"
}
```

#### **2. Document Metadata**
```bash
GET /documents/{documentId}/metadata
Headers:
  X-Gateway-Token: gateway-secret
  X-Request-ID: request-uuid
```

**Expected Response**:
```json
{
  "title": "Document Title",
  "type": "application/pdf",
  "size": 1024000,
  "createdAt": "2024-01-01T10:00:00Z",
  "modifiedAt": "2024-01-01T11:00:00Z"
}
```

#### **3. Document Content**
```bash
GET /documents/{documentId}/content
Headers:
  X-Gateway-Token: gateway-secret
  X-Request-ID: request-uuid
Response-Type: stream
```

**Expected Response**: Binary document stream

### **mTLS Configuration**

The gateway uses mutual TLS for private API communication:

```javascript
// Certificate paths
CLIENT_CERT_PATH=./certs/client.crt
CLIENT_KEY_PATH=./certs/client.key
CA_CERT_PATH=./certs/ca.crt

// Headers sent with every request
X-Gateway-Token: gateway-secret
X-Request-ID: uuid
```

## 📝 User Generation & Database Import

### **Generated User Data Structure**
```json
{
  "id": 1,
  "username": "user1",
  "email": "user1@example.com",
  "password": "Kj8#mN9$pL2",
  "password_hash": "$2b$12$8zRLfCqeOnsxyHrpySYpjuLdhe61gbQYk0z55ihi3jqcsl3WphGyG",
  "totp_secret": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  "biometric_enabled": false,
  "created_at": "2024-01-01T00:00:00.000Z"
}
```

### **Database Import Commands**

#### **PostgreSQL Import**
```bash
# Generate users with password hashes
npm run user:generate -- -c 10 -H -f csv -o users.csv

# Import to database
psql $DATABASE_URL -c "\COPY users(username, email, password_hash, totp_secret, created_at) FROM 'users.csv' CSV HEADER"
```

#### **Direct SQL Insert**
```sql
INSERT INTO users (username, email, password_hash, totp_secret, created_at)
VALUES 
  ('user1', 'user1@example.com', '$2b$12$hash...', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', NOW()),
  ('user2', 'user2@example.com', '$2b$12$hash...', 'BCDEFGHIJKLMNOPQRSTUVWXYZ234567A', NOW());
```

## 🚀 Complete Login Flow Example

### **1. Generate Test User**
```bash
# Generate user with 2FA
npm run user:generate -- -c 1 -p test -H -t -o test-user.json
```

### **2. Import to Database**
```bash
# Extract data and insert
jq -r '. | "INSERT INTO users (username, email, password_hash, totp_secret, created_at) VALUES (\'' + .username + '\', \'' + .email + '\', \'' + .password_hash + '\', \'' + .totp_secret + '\', NOW());"' test-user.json | psql $DATABASE_URL
```

### **3. Login Process**

#### **Step 1: Primary Auth**
```bash
curl -X POST http://localhost:3000/api/auth/primary \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test1",
    "password": "VD^!31KiF5#2"
  }'
```

#### **Step 2: Generate TOTP Code**
```bash
# Use the TOTP secret from generated user
# Generate code with any TOTP app (Google Authenticator, Authy, etc.)
# Or use speakeasy CLI: speakeasy totp --secret "352IQSCQ5IVHP7QW77354R3RQV24ZQYL"
```

#### **Step 3: Complete Auth**
```bash
curl -X POST http://localhost:3000/api/auth/complete \
  -H "Content-Type: application/json" \
  -d '{
    "challengeId": "challenge-id-from-step-1",
    "secondFactor": {
      "type": "otp",
      "value": "123456"
    },
    "deviceFingerprint": "device-hash"
  }'
```

### **4. Access Documents**
```bash
# Create secure document view
curl -X POST http://localhost:3000/api/documents/123/secure-view \
  -H "Authorization: Bearer access-token-from-step-3" \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "req-123",
    "timestamp": "2024-01-01T12:00:00Z"
  }'

# Access secure document
curl http://localhost:3000/api/documents/secure/view-token-from-response
```

## 🔧 Environment Configuration

### **Required Environment Variables**
```bash
# Database
DATABASE_URL=postgresql://user:pass@host:port/db

# JWT Secrets
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key

# Private API
PRIVATE_API_URL=https://private-api.internal
GATEWAY_SECRET=your-gateway-secret

# Redis (optional)
REDIS_URL=redis://host:port

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

### **Development Setup**
```bash
# Copy environment template
cp env.example .env

# Edit .env with your values
nano .env

# Run migrations
npm run migrate

# Generate test users
npm run user:generate -- -c 5 -H -t

# Start server
npm run dev
```

## 📊 Database Indexes

The system creates these indexes for performance:
```sql
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_document_access_logs_user_id ON document_access_logs(user_id);
CREATE INDEX idx_document_access_logs_document_id ON document_access_logs(document_id);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_event_type ON security_events(event_type);
CREATE INDEX idx_encrypted_metadata_user_document ON encrypted_metadata(user_id, document_id);
```

## 🔍 Monitoring & Logging

### **Health Check**
```bash
GET /api/health
Response: { "status": "healthy", "timestamp": "2024-01-01T12:00:00Z" }
```

### **Session Validation**
```bash
GET /api/session/validate
Headers: Authorization: Bearer token
Response: { "valid": true, "user": {...}, "expiresAt": "..." }
```

### **Audit Queries**
```sql
-- Recent login attempts
SELECT * FROM security_events 
WHERE event_type = 'failed_login' 
ORDER BY timestamp DESC LIMIT 10;

-- Document access by user
SELECT * FROM document_access_logs 
WHERE user_id = 1 
ORDER BY timestamp DESC;

-- Active sessions
SELECT * FROM sessions 
WHERE expires_at > NOW();
```

## 🚨 Security Considerations

1. **Password Security**: bcrypt with 12 rounds
2. **Account Lockout**: 4 failed attempts = 30-minute lock
3. **Session Management**: JWT with refresh tokens
4. **Rate Limiting**: 5 auth attempts per 15 minutes
5. **mTLS**: Mutual TLS for private API communication
6. **Audit Logging**: All access and security events logged
7. **CORS**: Configurable origin restrictions

This system provides enterprise-grade security with comprehensive audit trails and multi-factor authentication support. 