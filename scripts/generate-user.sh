#!/bin/bash

# Generate User Data Script
# Returns user data as JSON for automation and testing

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_COUNT=1
DEFAULT_PREFIX="user"
DEFAULT_DOMAIN="example.com"
DEFAULT_PASSWORD_LENGTH=12

# Function to show usage
show_usage() {
    echo -e "${BLUE}Generate User Data Script${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -c, --count NUMBER     Number of users to generate (default: $DEFAULT_COUNT)"
    echo "  -p, --prefix PREFIX    Username prefix (default: $DEFAULT_PREFIX)"
    echo "  -d, --domain DOMAIN    Email domain (default: $DEFAULT_DOMAIN)"
    echo "  -l, --length LENGTH    Password length (default: $DEFAULT_PASSWORD_LENGTH)"
    echo "  -t, --totp             Enable TOTP 2FA for all users"
    echo "  -b, --biometric        Enable biometric auth for all users"
    echo "  -H, --hash             Include bcrypt password hash"
    echo "  -f, --format FORMAT    Output format: json, csv, table (default: json)"
    echo "  -o, --output FILE      Output to file instead of stdout"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Generate 1 user with default settings"
    echo "  $0 -c 5 -p test              # Generate 5 users with 'test' prefix"
    echo "  $0 -c 10 -t -b               # Generate 10 users with 2FA enabled"
    echo "  $0 -c 3 -f csv -o users.csv  # Generate 3 users in CSV format"
    echo "  $0 -c 1 -H                   # Generate 1 user with password hash"
    echo ""
}

# Function to generate random string
generate_random_string() {
    local length=$1
    # Use LC_ALL=C to avoid locale issues
    LC_ALL=C cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1
}

# Function to generate random password
generate_password() {
    local length=$1
    # Generate password with at least one uppercase, lowercase, number, and special char
    # Use LC_ALL=C to avoid locale issues
    local password=$(LC_ALL=C cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*' | fold -w $length | head -n 1)
    echo "$password"
}

# Function to generate TOTP secret
generate_totp_secret() {
    # Generate 32-character base32 secret
    # Use LC_ALL=C to avoid locale issues
    LC_ALL=C cat /dev/urandom | LC_ALL=C tr -dc 'A-Z2-7' | fold -w 32 | head -n 1
}

# Function to find Node.js executable
find_node() {
    # Try common Node.js locations
    local node_paths=(
        "node"
        "npm"
        "$HOME/.nvm/versions/node/v22.17.1/bin/node"
        "$HOME/.nvm/versions/node/v22.14.0/bin/node"
        "/usr/local/bin/node"
        "/opt/homebrew/bin/node"
    )
    
    for path in "${node_paths[@]}"; do
        if command -v "$path" >/dev/null 2>&1; then
            echo "$path"
            return 0
        fi
    done
    
    # If npm is available, use it to run node
    if command -v "npm" >/dev/null 2>&1; then
        echo "npm exec node"
        return 0
    fi
    
    return 1
}

# Function to generate password hash using Node.js
generate_password_hash() {
    local password=$1
    local salt_rounds=${2:-12}
    
    # Find Node.js executable
    local node_cmd=$(find_node)
    if [ $? -ne 0 ]; then
        echo "❌ Node.js not found. Cannot generate password hash." >&2
        return 1
    fi
    
    # Use Node.js to generate bcrypt hash
    $node_cmd -e "
    const bcrypt = require('bcrypt');
    const password = '$password';
    const saltRounds = $salt_rounds;
    
    bcrypt.hash(password, saltRounds).then(hash => {
        console.log(hash);
    }).catch(err => {
        console.error('Error generating hash:', err.message);
        process.exit(1);
    });
    "
}

# Function to generate user data
generate_user_data() {
    local index=$1
    local prefix=$2
    local domain=$3
    local password_length=$4
    local enable_totp=$5
    local enable_biometric=$6
    local include_hash=$7
    
    local username="${prefix}${index}"
    local email="${username}@${domain}"
    local password=$(generate_password $password_length)
    local totp_secret=""
    local biometric_enabled="false"
    local password_hash=""
    
    if [ "$enable_totp" = "true" ]; then
        totp_secret=$(generate_totp_secret)
    fi
    
    if [ "$enable_biometric" = "true" ]; then
        biometric_enabled="true"
    fi
    
    if [ "$include_hash" = "true" ]; then
        password_hash=$(generate_password_hash "$password")
    fi
    
    # Generate JSON object
    cat << EOF
{
  "id": $index,
  "username": "$username",
  "email": "$email",
  "password": "$password"$(if [ "$include_hash" = "true" ]; then echo ",
  \"password_hash\": \"$password_hash\""; fi),
  "totp_secret": "$totp_secret",
  "biometric_enabled": $biometric_enabled,
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")",
  "qr_code_url": "$(if [ -n "$totp_secret" ]; then echo "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Gateway%20Server%20(${username})?secret=${totp_secret}&issuer=Secure%20Gateway"; fi)"
}
EOF
}

# Function to generate CSV header
generate_csv_header() {
    local include_hash=$1
    if [ "$include_hash" = "true" ]; then
        echo "id,username,email,password,password_hash,totp_secret,biometric_enabled,created_at,qr_code_url"
    else
        echo "id,username,email,password,totp_secret,biometric_enabled,created_at,qr_code_url"
    fi
}

# Function to generate CSV row
generate_csv_row() {
    local index=$1
    local prefix=$2
    local domain=$3
    local password_length=$4
    local enable_totp=$5
    local enable_biometric=$6
    local include_hash=$7
    
    local username="${prefix}${index}"
    local email="${username}@${domain}"
    local password=$(generate_password $password_length)
    local totp_secret=""
    local biometric_enabled="false"
    local password_hash=""
    
    if [ "$enable_totp" = "true" ]; then
        totp_secret=$(generate_totp_secret)
    fi
    
    if [ "$enable_biometric" = "true" ]; then
        biometric_enabled="true"
    fi
    
    if [ "$include_hash" = "true" ]; then
        password_hash=$(generate_password_hash "$password")
    fi
    
    local qr_code_url=""
    if [ -n "$totp_secret" ]; then
        qr_code_url="https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Gateway%20Server%20(${username})?secret=${totp_secret}&issuer=Secure%20Gateway"
    fi
    
    if [ "$include_hash" = "true" ]; then
        echo "$index,$username,$email,$password,$password_hash,$totp_secret,$biometric_enabled,$(date -u +"%Y-%m-%dT%H:%M:%S.000Z"),$qr_code_url"
    else
        echo "$index,$username,$email,$password,$totp_secret,$biometric_enabled,$(date -u +"%Y-%m-%dT%H:%M:%S.000Z"),$qr_code_url"
    fi
}

# Function to generate table format
generate_table_format() {
    local index=$1
    local prefix=$2
    local domain=$3
    local password_length=$4
    local enable_totp=$5
    local enable_biometric=$6
    
    local username="${prefix}${index}"
    local email="${username}@${domain}"
    local password=$(generate_password $password_length)
    local totp_secret=""
    local biometric_enabled="No"
    
    if [ "$enable_totp" = "true" ]; then
        totp_secret=$(generate_totp_secret)
    fi
    
    if [ "$enable_biometric" = "true" ]; then
        biometric_enabled="Yes"
    fi
    
    printf "%-3s | %-15s | %-25s | %-15s | %-8s | %-8s\n" \
           "$index" "$username" "$email" "${password:0:12}..." \
           "$(if [ -n "$totp_secret" ]; then echo "Yes"; else echo "No"; fi)" \
           "$biometric_enabled"
}

# Parse command line arguments
COUNT=$DEFAULT_COUNT
PREFIX=$DEFAULT_PREFIX
DOMAIN=$DEFAULT_DOMAIN
PASSWORD_LENGTH=$DEFAULT_PASSWORD_LENGTH
ENABLE_TOTP="false"
ENABLE_BIOMETRIC="false"
INCLUDE_HASH="false"
FORMAT="json"
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--count)
            COUNT="$2"
            shift 2
            ;;
        -p|--prefix)
            PREFIX="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -l|--length)
            PASSWORD_LENGTH="$2"
            shift 2
            ;;
        -t|--totp)
            ENABLE_TOTP="true"
            shift
            ;;
        -b|--biometric)
            ENABLE_BIOMETRIC="true"
            shift
            ;;
        -H|--hash)
            INCLUDE_HASH="true"
            shift
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Validate inputs
if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [ "$COUNT" -lt 1 ]; then
    echo -e "${RED}Error: Count must be a positive integer${NC}"
    exit 1
fi

if ! [[ "$PASSWORD_LENGTH" =~ ^[0-9]+$ ]] || [ "$PASSWORD_LENGTH" -lt 8 ]; then
    echo -e "${RED}Error: Password length must be at least 8 characters${NC}"
    exit 1
fi

# Check if output file is specified and create directory if needed
if [ -n "$OUTPUT_FILE" ]; then
    OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
    if [ "$OUTPUT_DIR" != "." ] && [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
    fi
fi

# Generate output
{
    case $FORMAT in
        "json")
            if [ "$COUNT" -eq 1 ]; then
                # Single user - return object
                generate_user_data 1 "$PREFIX" "$DOMAIN" "$PASSWORD_LENGTH" "$ENABLE_TOTP" "$ENABLE_BIOMETRIC" "$INCLUDE_HASH"
            else
                # Multiple users - return array
                echo "["
                for i in $(seq 1 $COUNT); do
                    if [ $i -gt 1 ]; then
                        echo ","
                    fi
                    generate_user_data $i "$PREFIX" "$DOMAIN" "$PASSWORD_LENGTH" "$ENABLE_TOTP" "$ENABLE_BIOMETRIC" "$INCLUDE_HASH"
                done
                echo "]"
            fi
            ;;
        "csv")
            generate_csv_header "$INCLUDE_HASH"
            for i in $(seq 1 $COUNT); do
                generate_csv_row $i "$PREFIX" "$DOMAIN" "$PASSWORD_LENGTH" "$ENABLE_TOTP" "$ENABLE_BIOMETRIC" "$INCLUDE_HASH"
            done
            ;;
        "table")
            echo "ID  | Username         | Email                     | Password       | TOTP     | Biometric"
            echo "----|------------------|---------------------------|----------------|----------|----------"
            for i in $(seq 1 $COUNT); do
                generate_table_format $i "$PREFIX" "$DOMAIN" "$PASSWORD_LENGTH" "$ENABLE_TOTP" "$ENABLE_BIOMETRIC"
            done
            ;;
        *)
            echo -e "${RED}Error: Invalid format '$FORMAT'. Use: json, csv, or table${NC}"
            exit 1
            ;;
    esac
} | if [ -n "$OUTPUT_FILE" ]; then
    tee "$OUTPUT_FILE"
    echo -e "${GREEN}✅ User data saved to: $OUTPUT_FILE${NC}"
else
    cat
fi

# Show summary
echo -e "${BLUE}📊 Generated $COUNT user(s) with prefix '$PREFIX'${NC}"
if [ "$ENABLE_TOTP" = "true" ]; then
    echo -e "${YELLOW}🔐 TOTP 2FA enabled for all users${NC}"
fi
if [ "$ENABLE_BIOMETRIC" = "true" ]; then
    echo -e "${YELLOW}📱 Biometric authentication enabled for all users${NC}"
fi
if [ "$INCLUDE_HASH" = "true" ]; then
    echo -e "${YELLOW}🔒 Password hashes included for database import${NC}"
fi 