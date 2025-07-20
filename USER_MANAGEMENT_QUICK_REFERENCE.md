# User Management - Quick Reference

## 🚀 Quick Start

```bash
# Add a user
npm run user:add

# Production (Railway)
railway run npm run user:add
```

## 👤 User Creation Process

1. **Run script** → `npm run user:add`
2. **Enter details**:
   - Username (3-50 chars)
   - Email (optional)
   - Password (8+ chars)
   - Confirm password
   - Enable TOTP 2FA? (y/N)
   - Enable biometric? (y/N)
3. **Complete setup** → User created with secure hash

## 📋 Interactive Menu

| Option | Action |
|--------|--------|
| **1** | Add new user |
| **2** | List all users |
| **3** | Exit |

## 🔐 Two-Factor Authentication (TOTP)

### **Setup**
- Enable during user creation
- Scan QR code with authenticator app
- Enter code during login

### **Supported Apps**
- Google Authenticator
- Authy
- Microsoft Authenticator
- 1Password

### **QR Code Format**
```
otpauth://totp/Gateway Server (username)?secret=SECRET&issuer=Secure Gateway
```

## 🌐 Environment Usage

### **Local Development**
```bash
export DB_HOST=localhost
export DB_USER=postgres
export DB_PASSWORD=your_password
export DB_NAME=secure_docs
npm run user:add
```

### **Railway Production**
```bash
railway run npm run user:add
```

### **Docker**
```bash
docker exec -it container npm run user:add
```

## 🛠️ Database Operations

### **View Users**
```sql
SELECT id, username, email, created_at, last_login, failed_attempts 
FROM users ORDER BY created_at DESC;
```

### **Check User Status**
```sql
SELECT username, failed_attempts, locked_until 
FROM users WHERE username = 'username';
```

### **Reset Failed Attempts**
```sql
UPDATE users 
SET failed_attempts = 0, locked_until = NULL 
WHERE username = 'username';
```

### **Update Password**
```sql
UPDATE users 
SET password_hash = 'new_hash' 
WHERE username = 'username';
```

## 🔍 User Monitoring

### **Recent Activity**
```sql
-- Recent logins
SELECT username, last_login, failed_attempts 
FROM users 
WHERE last_login > NOW() - INTERVAL '7 days';

-- Locked accounts
SELECT username, failed_attempts, locked_until 
FROM users 
WHERE locked_until > NOW();
```

### **Security Events**
```sql
-- Failed logins
SELECT * FROM security_events 
WHERE event_type = 'failed_login' 
ORDER BY timestamp DESC;

-- Successful logins
SELECT * FROM security_events 
WHERE event_type = 'successful_login' 
ORDER BY timestamp DESC;
```

## 🚨 Troubleshooting

### **Common Issues**

| Issue | Check | Fix |
|-------|-------|-----|
| **Database connection** | `echo $DATABASE_URL` | Set environment variables |
| **User exists** | List users | Choose different username |
| **Password too short** | 8+ characters | Use stronger password |
| **TOTP not working** | Time sync | Check device time |

### **Recovery Commands**

```sql
-- Unlock account
UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = 'username';

-- Disable 2FA
UPDATE users SET totp_secret = NULL WHERE username = 'username';

-- Reset password
UPDATE users SET password_hash = 'new_hash' WHERE username = 'username';
```

## 📊 User Data Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | SERIAL | Unique identifier |
| `username` | VARCHAR(255) | Login username |
| `email` | VARCHAR(255) | Contact email |
| `password_hash` | VARCHAR(255) | Bcrypt hash |
| `totp_secret` | VARCHAR(255) | 2FA secret |
| `biometric_credentials` | JSONB | Biometric data |
| `created_at` | TIMESTAMP | Account creation |
| `last_login` | TIMESTAMP | Last login |
| `failed_attempts` | INTEGER | Failed login count |
| `locked_until` | TIMESTAMP | Lockout until |

## 🎯 Security Features

- ✅ **Password Hashing** - Bcrypt with configurable rounds
- ✅ **Account Lockout** - Auto-lock after 5 failed attempts
- ✅ **TOTP 2FA** - Time-based one-time passwords
- ✅ **Biometric Support** - Mobile authentication
- ✅ **Session Management** - Secure session handling
- ✅ **Audit Logging** - All actions logged

## 📖 Full Documentation

See `docs/USER_MANAGEMENT.md` for complete guide. 