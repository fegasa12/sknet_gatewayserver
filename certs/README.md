# SSL/TLS Certificates

This directory contains SSL/TLS certificates for mTLS (mutual TLS) communication with the private API.

## Required Files

For mTLS to work, you need the following files:

- `client.crt` - Client certificate
- `client.key` - Client private key  
- `ca.crt` - Certificate Authority certificate

## Setup Instructions

### For Development

1. Generate self-signed certificates for development:
   ```bash
   # Generate CA certificate
   openssl genrsa -out ca.key 2048
   openssl req -new -x509 -days 365 -key ca.key -out ca.crt
   
   # Generate client certificate
   openssl genrsa -out client.key 2048
   openssl req -new -key client.key -out client.csr
   openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
   ```

2. Copy the generated files to this directory:
   ```bash
   cp client.crt client.key ca.crt certs/
   ```

### For Production

1. Obtain proper certificates from your certificate authority
2. Place the certificates in this directory
3. Update the environment variables:
   - `CLIENT_CERT_PATH=./certs/client.crt`
   - `CLIENT_KEY_PATH=./certs/client.key`
   - `CA_CERT_PATH=./certs/ca.crt`

## Security Notes

- **Never commit private keys** to version control
- **Use strong passwords** for private keys
- **Rotate certificates** regularly
- **Store production certificates** securely

## Railway Deployment

For Railway deployment, you can:

1. Store certificates as environment variables (base64 encoded)
2. Use Railway's secret management
3. Mount certificates as files in the deployment

Example for Railway:
```bash
# Encode certificates
base64 -w 0 client.crt > client.crt.b64
base64 -w 0 client.key > client.key.b64
base64 -w 0 ca.crt > ca.crt.b64

# Set as Railway variables
railway variables set CLIENT_CERT_B64="$(cat client.crt.b64)"
railway variables set CLIENT_KEY_B64="$(cat client.key.b64)"
railway variables set CA_CERT_B64="$(cat ca.crt.b64)"
```

Then modify the server to decode these variables at runtime. 