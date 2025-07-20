# User Management Guide

This guide explains how to manage users in your Secure Gateway Server.

## 🚀 Quick Start

### **Add a User**

```bash
# Local development
npm run user:add

# Production (Railway)
railway run npm run user:add
```

### **Interactive Menu**

The script provides an interactive menu:
1. **Add new user** - Create a new user account
2. **List all users** - View existing users
3. **Exit** - Close the application

## 👤 Adding Users

### **Step-by-Step Process**

1. **Run the script:**
   ```bash
   npm run user:add
   ```

2. **Follow the prompts:**
   - **Username** (required, 3-50 characters)
   - **Email** (optional, valid email format)
   - **Password** (required, minimum 8 characters)
   - **Confirm Password** (must match)
   - **Enable TOTP 2FA** (y/N)
   - **Enable biometric authentication** (y/N)

3. **Complete setup:**
   - User is created in database
   - Password is securely hashed
   - TOTP secret generated (if enabled)
   - QR code URL provided for 2FA setup

### **Example Session**

```bash
$ npm run user:add

🔐 Secure Gateway Server - User Management

✅ Database connected successfully

📋 User Management Menu:
1. Add new user
2. List all users
3. Exit

Select option (1-3): 1

👤 Add New User

Username: john.doe
Email (optional): john@example.com
Password: ********
Confirm Password: ********
Enable TOTP 2FA? (y/N): y
Enable biometric authentication? (y/N): n

✅ User created successfully!
📋 User Details:
   ID: 1
   Username: john.doe
   Email: john@example.com
   Created: 2024-01-01T00:00:00.000Z
   TOTP 2FA: Enabled
   Biometric: Disabled

🔐 TOTP Setup:
   Secret: ABCDEFGHIJKLMNOP
   QR Code URL: https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Gateway%20Server%20(john.doe)?secret=ABCDEFGHIJKLMNOP&issuer=Secure%20Gateway

💡 Use Google Authenticator, Authy, or any TOTP app to scan the QR code
```

## 📋 User Information

### **Stored Data**

Each user record contains:
- **ID** - Unique identifier
- **Username** - Login username
- **Email** - Contact email (optional)
- **Password Hash** - Securely hashed password
- **TOTP Secret** - 2FA secret (if enabled)
- **Biometric Credentials** - Biometric data (if enabled)
- **Created At** - Account creation timestamp
- **Last Login** - Last successful login
- **Failed Attempts** - Count of failed login attempts
- **Locked Until** - Account lockout timestamp

### **Security Features**

- **Password Hashing** - Bcrypt with configurable rounds
- **Account Lockout** - Automatic after 5 failed attempts
- **TOTP 2FA** - Time-based one-time passwords
- **Biometric Support** - For mobile authentication
- **Session Management** - Secure session handling

## 🔐 Two-Factor Authentication (TOTP)

### **Setup Process**

1. **Enable during user creation** or update existing user
2. **Scan QR code** with authenticator app
3. **Enter generated code** during login
4. **Complete authentication** with username/password + TOTP

### **Supported Apps**

- Google Authenticator
- Authy
- Microsoft Authenticator
- 1Password
- Any TOTP-compatible app

### **QR Code Format**

```
otpauth://totp/Gateway Server (username)?secret=SECRET&issuer=Secure Gateway
```

## 🌐 Environment-Specific Usage

### **Local Development**

```bash
# Set database connection
export DB_HOST=localhost
export DB_USER=postgres
export DB_PASSWORD=your_password
export DB_NAME=secure_docs

# Run user management
npm run user:add
```

### **Railway Production**

```bash
# Railway automatically provides DATABASE_URL
railway run npm run user:add
```

### **Docker/Container**

```bash
# Run inside container
docker exec -it your-container npm run user:add
```

## 🛠️ Advanced Operations

### **Database Direct Access**

```sql
-- View all users
SELECT id, username, email, created_at, last_login, failed_attempts 
FROM users ORDER BY created_at DESC;

-- Check user status
SELECT username, failed_attempts, locked_until 
FROM users WHERE username = 'john.doe';

-- Reset failed attempts
UPDATE users SET failed_attempts = 0, locked_until = NULL 
WHERE username = 'john.doe';

-- Update password
UPDATE users SET password_hash = 'new_hash' 
WHERE username = 'john.doe';
```

### **Bulk User Import**

For large user imports, create a CSV file and use:

```javascript
// Example bulk import script
const csv = require('csv-parser');
const fs = require('fs');
const { addUser } = require('./scripts/add-user.js');

fs.createReadStream('users.csv')
  .pipe(csv())
  .on('data', async (row) => {
    // Process each user
    await addUser(row.username, row.email, row.password);
  });
```

## 🔍 User Monitoring

### **Login Activity**

```sql
-- Recent logins
SELECT username, last_login, failed_attempts 
FROM users 
WHERE last_login > NOW() - INTERVAL '7 days'
ORDER BY last_login DESC;

-- Locked accounts
SELECT username, failed_attempts, locked_until 
FROM users 
WHERE locked_until > NOW();
```

### **Security Events**

```sql
-- Failed login attempts
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

**1. Database Connection Failed**
```bash
# Check environment variables
echo $DATABASE_URL

# Test connection
psql $DATABASE_URL -c "SELECT NOW();"
```

**2. User Already Exists**
- Choose a different username
- Check existing users with "List all users"

**3. Password Requirements**
- Minimum 8 characters
- Consider complexity requirements
- Use strong, unique passwords

**4. TOTP Setup Issues**
- Ensure QR code is scanned correctly
- Check time synchronization on device
- Verify secret is entered correctly

### **Recovery Procedures**

**Reset User Password:**
```sql
UPDATE users 
SET password_hash = 'new_hash', failed_attempts = 0, locked_until = NULL 
WHERE username = 'username';
```

**Unlock Account:**
```sql
UPDATE users 
SET failed_attempts = 0, locked_until = NULL 
WHERE username = 'username';
```

**Disable 2FA:**
```sql
UPDATE users 
SET totp_secret = NULL 
WHERE username = 'username';
```

## 📊 Best Practices

### **User Creation**

- Use strong, unique passwords
- Enable 2FA for sensitive accounts
- Provide clear setup instructions
- Document user roles and permissions

### **Security**

- Regularly audit user accounts
- Monitor failed login attempts
- Implement password policies
- Use secure communication channels

### **Maintenance**

- Clean up inactive accounts
- Update user information regularly
- Backup user data securely
- Monitor system logs

## 🎯 Next Steps

1. **Create your first user** with `npm run user:add`
2. **Set up 2FA** for enhanced security
3. **Test authentication** with the new user
4. **Monitor user activity** through logs
5. **Implement user roles** if needed

Your user management system is now ready! 🎉 