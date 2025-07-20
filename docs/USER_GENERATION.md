# User Generation Script Guide

This guide explains how to use the user generation script to create test users and bulk user data.

## 🚀 Quick Start

### **Generate a Single User (JSON)**

```bash
# Generate 1 user with default settings
npm run user:generate

# Or directly
./scripts/generate-user.sh
```

### **Generate Multiple Users**

```bash
# Generate 5 users
npm run user:generate -- -c 5

# Generate 10 users with custom prefix
npm run user:generate -- -c 10 -p test
```

## 📋 Script Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-c, --count` | Number of users to generate | 1 | `-c 5` |
| `-p, --prefix` | Username prefix | "user" | `-p admin` |
| `-d, --domain` | Email domain | "example.com" | `-d mycompany.com` |
| `-l, --length` | Password length | 12 | `-l 16` |
| `-t, --totp` | Enable TOTP 2FA | false | `-t` |
| `-b, --biometric` | Enable biometric auth | false | `-b` |
| `-H, --hash` | Include bcrypt password hash | false | `-H` |
| `-f, --format` | Output format | "json" | `-f csv` |
| `-o, --output` | Output file | stdout | `-o users.json` |
| `-h, --help` | Show help | - | `-h` |

## 🎯 Use Cases

### **1. Test User Generation**

```bash
# Generate test users for development
npm run user:generate -- -c 3 -p test -d test.local

# Generate users with 2FA enabled
npm run user:generate -- -c 5 -p test -t

# Generate users with password hashes for database import
npm run user:generate -- -c 3 -p test -H
```

### **2. Bulk User Creation**

```bash
# Generate 100 users for load testing
npm run user:generate -- -c 100 -p loadtest -o loadtest-users.json

# Generate users with biometric enabled
npm run user:generate -- -c 50 -p mobile -b -o mobile-users.json
```

### **3. Different Output Formats**

```bash
# JSON format (default)
npm run user:generate -- -c 3 -f json

# CSV format
npm run user:generate -- -c 3 -f csv -o users.csv

# Table format (human readable)
npm run user:generate -- -c 3 -f table
```

## 📊 Output Formats

### **JSON Format**

```json
[
  {
    "id": 1,
    "username": "user1",
    "email": "user1@example.com",
    "password": "Kj8#mN9$pL2",
    "password_hash": "$2b$12$8zRLfCqeOnsxyHrpySYpjuLdhe61gbQYk0z55ihi3jqcsl3WphGyG",
    "totp_secret": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    "biometric_enabled": false,
    "created_at": "2024-01-01T00:00:00.000Z",
    "qr_code_url": "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Gateway%20Server%20(user1)?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=Secure%20Gateway"
  }
]
```

### **CSV Format**

```csv
id,username,email,password,password_hash,totp_secret,biometric_enabled,created_at,qr_code_url
1,user1,user1@example.com,Kj8#mN9$pL2,$2b$12$8zRLfCqeOnsxyHrpySYpjuLdhe61gbQYk0z55ihi3jqcsl3WphGyG,ABCDEFGHIJKLMNOPQRSTUVWXYZ234567,false,2024-01-01T00:00:00.000Z,https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Gateway%20Server%20(user1)?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=Secure%20Gateway
```

### **Table Format**

```
ID  | Username         | Email                     | Password       | TOTP     | Biometric
----|------------------|---------------------------|----------------|----------|----------
1   | user1            | user1@example.com         | Kj8#mN9$pL2... | Yes      | No
2   | user2            | user2@example.com         | Xy7#kL8$mN3... | No       | Yes
```

## 🔐 Security Features

### **Password Generation**

- **Minimum length**: 8 characters
- **Character set**: A-Z, a-z, 0-9, !@#$%^&*
- **Random generation**: Uses `/dev/urandom`
- **Configurable length**: Set with `-l` option

### **Password Hashing**

- **Algorithm**: bcrypt with configurable salt rounds (default: 12)
- **Format**: `$2b$12$...` (bcrypt format)
- **Security**: Industry-standard hashing for password storage
- **Usage**: Include with `-H` flag for database import
- **Compatibility**: Works with existing authentication system

### **TOTP Secret Generation**

- **Format**: Base32 encoded
- **Length**: 32 characters
- **Compatible**: Works with all TOTP apps
- **QR Code**: Automatically generated

### **Biometric Support**

- **Flag**: Enable with `-b` option
- **Data**: JSON array format
- **Compatible**: Mobile authentication ready

## 🛠️ Integration Examples

### **1. Automated Testing**

```bash
#!/bin/bash
# Generate test users for automated testing

# Generate 10 test users
npm run user:generate -- -c 10 -p test -t -o test-users.json

# Use the generated data in tests
jq -r '.[] | "\(.username):\(.password)"' test-users.json > test-credentials.txt
```

### **2. Load Testing**

```bash
#!/bin/bash
# Generate users for load testing

# Generate 1000 users
npm run user:generate -- -c 1000 -p loadtest -o loadtest-users.json

# Extract usernames for load testing
jq -r '.[].username' loadtest-users.json > usernames.txt
```

### **3. Development Setup**

```bash
#!/bin/bash
# Setup development environment with test users

# Generate admin user
npm run user:generate -- -c 1 -p admin -t -o admin-user.json

# Generate regular users
npm run user:generate -- -c 5 -p user -o regular-users.json

# Generate mobile users
npm run user:generate -- -c 3 -p mobile -b -o mobile-users.json
```

### **4. Import to Database**

```bash
#!/bin/bash
# Import generated users to database

# Generate users with password hashes
npm run user:generate -- -c 10 -p import -H -f csv -o users.csv

# Import using psql (example)
psql $DATABASE_URL -c "\COPY users(username, email, password_hash) FROM 'users.csv' CSV HEADER"
```

## 📈 Advanced Usage

### **Custom Scripts**

```bash
#!/bin/bash
# Custom user generation script

# Generate different user types
echo "Generating admin users..."
npm run user:generate -- -c 3 -p admin -t -o admin-users.json

echo "Generating regular users..."
npm run user:generate -- -c 20 -p user -o regular-users.json

echo "Generating mobile users..."
npm run user:generate -- -c 10 -p mobile -b -o mobile-users.json

# Combine all users
jq -s 'add' admin-users.json regular-users.json mobile-users.json > all-users.json
```

### **Environment-Specific Generation**

```bash
#!/bin/bash
# Generate users for different environments

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
    echo "⚠️  Be careful with production user generation!"
    npm run user:generate -- -c $COUNT -p prod -d company.com -t -b -o prod-users.json
    ;;
  *)
    echo "Usage: $0 {dev|staging|prod} [count]"
    exit 1
    ;;
esac
```

## 🔍 Data Validation

### **JSON Validation**

```bash
# Validate generated JSON
npm run user:generate -- -c 3 -o users.json
jq '.' users.json > /dev/null && echo "✅ Valid JSON" || echo "❌ Invalid JSON"
```

### **CSV Validation**

```bash
# Validate generated CSV
npm run user:generate -- -c 3 -f csv -o users.csv
head -1 users.csv | tr ',' '\n' | wc -l  # Should be 8 columns
```

### **Password Strength Check**

```bash
# Check password strength
npm run user:generate -- -c 1 | jq -r '.password' | grep -E '.{8,}' && echo "✅ Password length OK" || echo "❌ Password too short"
```

## 🚨 Best Practices

### **Security**

- **Never commit** generated user files to version control
- **Use strong passwords** (increase length with `-l`)
- **Enable 2FA** for sensitive accounts (`-t`)
- **Rotate secrets** regularly

### **File Management**

- **Use descriptive filenames** with timestamps
- **Store in secure location** (not in git)
- **Clean up old files** regularly
- **Backup important user data**

### **Automation**

- **Use in CI/CD** for test data generation
- **Parameterize scripts** for different environments
- **Validate output** before using
- **Log generation activities**

## 📖 Examples

### **Complete Workflow**

```bash
#!/bin/bash
# Complete user generation workflow

echo "🔐 Generating test users..."

# Generate admin user
npm run user:generate -- -c 1 -p admin -t -o admin-user.json
echo "✅ Admin user generated"

# Generate regular users
npm run user:generate -- -c 10 -p user -o regular-users.json
echo "✅ Regular users generated"

# Generate mobile users
npm run user:generate -- -c 5 -p mobile -b -o mobile-users.json
echo "✅ Mobile users generated"

# Create summary
echo "📊 User Generation Summary:"
echo "  - Admin users: 1"
echo "  - Regular users: 10"
echo "  - Mobile users: 5"
echo "  - Total: 16 users"

# Show file sizes
echo "📁 Generated files:"
ls -lh *.json
```

Your user generation system is now ready for automation and testing! 🎉 