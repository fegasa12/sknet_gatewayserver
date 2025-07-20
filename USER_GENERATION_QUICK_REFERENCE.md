# User Generation - Quick Reference

## 🚀 Quick Start

```bash
# Generate 1 user (JSON)
npm run user:generate

# Generate 5 users
npm run user:generate -- -c 5

# Generate with 2FA
npm run user:generate -- -c 3 -t
```

## 📋 Command Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-c, --count` | Number of users | 1 | `-c 10` |
| `-p, --prefix` | Username prefix | "user" | `-p admin` |
| `-d, --domain` | Email domain | "example.com" | `-d company.com` |
| `-l, --length` | Password length | 12 | `-l 16` |
| `-t, --totp` | Enable 2FA | false | `-t` |
| `-b, --biometric` | Enable biometric | false | `-b` |
| `-f, --format` | Output format | "json" | `-f csv` |
| `-o, --output` | Output file | stdout | `-o users.json` |
| `-h, --help` | Show help | - | `-h` |

## 🎯 Common Use Cases

### **Test Users**
```bash
# Development testing
npm run user:generate -- -c 5 -p test -d test.local

# With 2FA enabled
npm run user:generate -- -c 3 -p test -t
```

### **Bulk Generation**
```bash
# Load testing
npm run user:generate -- -c 100 -p loadtest -o loadtest-users.json

# Mobile users
npm run user:generate -- -c 50 -p mobile -b -o mobile-users.json
```

### **Different Formats**
```bash
# JSON (default)
npm run user:generate -- -c 3 -f json

# CSV
npm run user:generate -- -c 3 -f csv -o users.csv

# Table (human readable)
npm run user:generate -- -c 3 -f table
```

## 📊 Output Examples

### **JSON Format**
```json
{
  "id": 1,
  "username": "user1",
  "email": "user1@example.com",
  "password": "Kj8#mN9$pL2",
  "totp_secret": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  "biometric_enabled": false,
  "created_at": "2024-01-01T00:00:00.000Z",
  "qr_code_url": "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Gateway%20Server%20(user1)?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=Secure%20Gateway"
}
```

### **CSV Format**
```csv
id,username,email,password,totp_secret,biometric_enabled,created_at,qr_code_url
1,user1,user1@example.com,Kj8#mN9$pL2,ABCDEFGHIJKLMNOPQRSTUVWXYZ234567,false,2024-01-01T00:00:00.000Z,https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Gateway%20Server%20(user1)?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=Secure%20Gateway
```

### **Table Format**
```
ID  | Username         | Email                     | Password       | TOTP     | Biometric
----|------------------|---------------------------|----------------|----------|----------
1   | user1            | user1@example.com         | Kj8#mN9$pL2... | Yes      | No
```

## 🔐 Security Features

- ✅ **Strong Passwords** - 8+ chars, mixed case, symbols
- ✅ **TOTP Secrets** - Base32 encoded, 32 chars
- ✅ **QR Codes** - Auto-generated for 2FA setup
- ✅ **Random Generation** - Uses `/dev/urandom`
- ✅ **Biometric Support** - Mobile auth ready

## 🛠️ Integration Examples

### **Automated Testing**
```bash
# Generate test users
npm run user:generate -- -c 10 -p test -t -o test-users.json

# Extract credentials
jq -r '.[] | "\(.username):\(.password)"' test-users.json > credentials.txt
```

### **Load Testing**
```bash
# Generate 1000 users
npm run user:generate -- -c 1000 -p loadtest -o loadtest-users.json

# Extract usernames
jq -r '.[].username' loadtest-users.json > usernames.txt
```

### **Development Setup**
```bash
# Admin user
npm run user:generate -- -c 1 -p admin -t -o admin-user.json

# Regular users
npm run user:generate -- -c 5 -p user -o regular-users.json

# Mobile users
npm run user:generate -- -c 3 -p mobile -b -o mobile-users.json
```

### **Database Import**
```bash
# Generate CSV
npm run user:generate -- -c 10 -p import -f csv -o users.csv

# Import to database
psql $DATABASE_URL -c "\COPY users(username, email) FROM 'users.csv' CSV HEADER"
```

## 🚨 Best Practices

### **Security**
- Never commit generated files to git
- Use strong passwords (increase length with `-l`)
- Enable 2FA for sensitive accounts (`-t`)
- Rotate secrets regularly

### **File Management**
- Use descriptive filenames with timestamps
- Store in secure location (not in git)
- Clean up old files regularly
- Backup important user data

### **Automation**
- Use in CI/CD for test data generation
- Parameterize scripts for different environments
- Validate output before using
- Log generation activities

## 📈 Advanced Scripts

### **Environment-Specific Generation**
```bash
#!/bin/bash
ENVIRONMENT=$1
COUNT=${2:-5}

case $ENVIRONMENT in
  "dev")
    npm run user:generate -- -c $COUNT -p dev -d dev.local -o dev-users.json
    ;;
  "staging")
    npm run user:generate -- -c $COUNT -p staging -d staging.company.com -t -o staging-users.json
    ;;
  "prod")
    echo "⚠️  Be careful with production!"
    npm run user:generate -- -c $COUNT -p prod -d company.com -t -b -o prod-users.json
    ;;
esac
```

### **Complete Workflow**
```bash
#!/bin/bash
echo "🔐 Generating test users..."

# Generate different user types
npm run user:generate -- -c 1 -p admin -t -o admin-user.json
npm run user:generate -- -c 10 -p user -o regular-users.json
npm run user:generate -- -c 5 -p mobile -b -o mobile-users.json

echo "📊 Generated: 1 admin, 10 regular, 5 mobile users"
ls -lh *.json
```

## 🔍 Validation

### **JSON Validation**
```bash
npm run user:generate -- -c 3 -o users.json
jq '.' users.json > /dev/null && echo "✅ Valid JSON" || echo "❌ Invalid JSON"
```

### **Password Strength**
```bash
npm run user:generate -- -c 1 | jq -r '.password' | grep -E '.{8,}' && echo "✅ Password OK" || echo "❌ Password too short"
```

## 📖 Full Documentation

See `docs/USER_GENERATION.md` for complete guide. 