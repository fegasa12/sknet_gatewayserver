# Database & API Quick Reference

## 📊 Database Tables

| Table | Purpose | Key Fields |
|-------|---------|------------|
| **users** | User authentication | username, password_hash, totp_secret, biometric_credentials |
| **sessions** | Active sessions | id (UUID), user_id, expires_at, device_fingerprint |
| **document_access_logs** | Audit trail | user_id, document_id, action, metadata |
| **security_events** | Security logging | event_type, user_id, data |
| **encrypted_metadata** | User-specific metadata | user_id, document_id, encrypted_data |

## 🔐 Authentication Flow

### **1. Primary Auth**
```bash
POST /api/auth/primary
{
  "username": "user1",
  "password": "password123"
}
```

### **2. Complete Auth (MFA)**
```bash
POST /api/auth/complete
{
  "challengeId": "uuid",
  "secondFactor": {
    "type": "otp",
    "value": "123456"
  }
}
```

## 🔗 Private API Endpoints

| Endpoint | Method | Purpose | Headers |
|----------|--------|---------|---------|
| `/documents/{id}/access` | GET | Check access | X-Gateway-Token, X-User-ID |
| `/documents/{id}/metadata` | GET | Get metadata | X-Gateway-Token |
| `/documents/{id}/content` | GET | Get content | X-Gateway-Token |

## 📝 User Generation & Import

### **Generate Users**
```bash
# Generate with password hash
npm run user:generate -- -c 5 -H -t

# Generate CSV for import
npm run user:generate -- -c 10 -H -f csv -o users.csv
```

### **Database Import**
```bash
# PostgreSQL import
psql $DATABASE_URL -c "\COPY users(username, email, password_hash, totp_secret) FROM 'users.csv' CSV HEADER"

# Direct SQL
INSERT INTO users (username, email, password_hash, totp_secret) 
VALUES ('user1', 'user1@example.com', '$2b$12$hash...', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
```

## 🚀 Complete Login Example

### **1. Generate Test User**
```bash
npm run user:generate -- -c 1 -p test -H -t -o test-user.json
```

### **2. Import to Database**
```bash
# Extract and insert
jq -r '. | "INSERT INTO users (username, email, password_hash, totp_secret) VALUES (\'' + .username + '\', \'' + .email + '\', \'' + .password_hash + '\', \'' + .totp_secret + '\');"' test-user.json | psql $DATABASE_URL
```

### **3. Login Process**
```bash
# Step 1: Primary auth
curl -X POST http://localhost:3000/api/auth/primary \
  -H "Content-Type: application/json" \
  -d '{"username": "test1", "password": "password-from-generated-user"}'

# Step 2: Complete auth with TOTP
curl -X POST http://localhost:3000/api/auth/complete \
  -H "Content-Type: application/json" \
  -d '{
    "challengeId": "challenge-id-from-step-1",
    "secondFactor": {"type": "otp", "value": "123456"}
  }'
```

## 🔧 Environment Variables

### **Required**
```bash
DATABASE_URL=postgresql://user:pass@host:port/db
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
PRIVATE_API_URL=https://private-api.internal
GATEWAY_SECRET=your-gateway-secret
```

### **Optional**
```bash
REDIS_URL=redis://host:port
ALLOWED_ORIGINS=https://yourdomain.com
BCRYPT_ROUNDS=12
```

## 📊 Database Schema Details

### **Users Table**
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

### **Sessions Table**
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

## 🔍 Monitoring Queries

### **Recent Login Attempts**
```sql
SELECT * FROM security_events 
WHERE event_type = 'failed_login' 
ORDER BY timestamp DESC LIMIT 10;
```

### **Active Sessions**
```sql
SELECT * FROM sessions 
WHERE expires_at > NOW();
```

### **Document Access by User**
```sql
SELECT * FROM document_access_logs 
WHERE user_id = 1 
ORDER BY timestamp DESC;
```

## 🚨 Security Features

- ✅ **Password Security**: bcrypt with 12 rounds
- ✅ **Account Lockout**: 4 failed attempts = 30-minute lock
- ✅ **Session Management**: JWT with refresh tokens
- ✅ **Rate Limiting**: 5 auth attempts per 15 minutes
- ✅ **mTLS**: Mutual TLS for private API
- ✅ **Audit Logging**: All access and security events
- ✅ **CORS**: Configurable origin restrictions

## 📡 API Endpoints

### **Authentication**
- `POST /api/auth/primary` - Primary authentication
- `POST /api/auth/complete` - Complete MFA authentication
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - Logout and invalidate session

### **Session Management**
- `GET /api/session/validate` - Validate current session
- `GET /api/session/public-key` - Get session public key

### **Document Management**
- `POST /api/documents/:id/secure-view` - Create secure document view
- `GET /api/documents/secure/:token` - Serve secure document

### **Health Check**
- `GET /api/health` - Server health status

## 🔄 Setup Commands

```bash
# Setup environment
cp env.example .env
nano .env

# Run migrations
npm run migrate

# Generate test users
npm run user:generate -- -c 5 -H -t

# Start server
npm run dev
```

## 📖 Full Documentation

See `docs/DATABASE_AND_API_GUIDE.md` for complete guide. 