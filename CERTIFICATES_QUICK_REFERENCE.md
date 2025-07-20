# SSL Certificates - Quick Reference

## 🚀 Quick Start (Development)

```bash
# 1. Generate certificates
npm run certs
# OR
./scripts/generate-dev-certs.sh

# 2. Start server with HTTPS
NODE_ENV=development node src/server.js
```

## 📁 Certificate Files

| File | Purpose | Required |
|------|---------|----------|
| `./certs/server.key` | Server private key | HTTPS |
| `./certs/server.crt` | Server certificate | HTTPS |
| `./certs/client.key` | Client private key | mTLS |
| `./certs/client.crt` | Client certificate | mTLS |
| `./certs/ca.key` | CA private key | mTLS |
| `./certs/ca.crt` | CA certificate | mTLS |

## 🔧 Environment Variables

```bash
# Server HTTPS
SSL_KEY_PATH=./certs/server.key
SSL_CERT_PATH=./certs/server.crt

# Client mTLS
CLIENT_CERT_PATH=./certs/client.crt
CLIENT_KEY_PATH=./certs/client.key
CA_CERT_PATH=./certs/ca.crt
```

## 🧪 Testing

```bash
# Test HTTPS (ignore self-signed warning)
curl -k https://localhost:3001/api/health

# Test with certificate validation
curl --cacert ./certs/server.crt https://localhost:3001/api/health
```

## 🔒 Production Options

1. **Let's Encrypt** (Free)
2. **Commercial CA** (DigiCert, GlobalSign, etc.)
3. **Cloud Platform** (Railway, Heroku, AWS, etc.)

## ⚠️ Security Notes

- Never commit private keys to git
- Set proper permissions: `chmod 600 *.key`
- Monitor certificate expiration
- Use trusted CAs in production

## 📖 Full Documentation

See `docs/CERTIFICATES.md` for complete guide. 