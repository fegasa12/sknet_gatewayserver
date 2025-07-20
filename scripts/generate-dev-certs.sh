#!/bin/bash

# Generate Self-Signed SSL Certificates for Development
# This script creates certificates for local development

echo "🔐 Generating self-signed SSL certificates for development..."

# Create certs directory if it doesn't exist
mkdir -p ./certs

# Generate private key
openssl genrsa -out ./certs/server.key 2048

# Generate certificate signing request (CSR)
openssl req -new -key ./certs/server.key -out ./certs/server.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in ./certs/server.csr -signkey ./certs/server.key -out ./certs/server.crt

# Generate client certificates for mTLS (mutual TLS)
echo "🔐 Generating client certificates for mTLS..."

# Generate CA private key
openssl genrsa -out ./certs/ca.key 2048

# Generate CA certificate
openssl req -new -x509 -days 365 -key ./certs/ca.key -out ./certs/ca.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=Gateway-CA"

# Generate client private key
openssl genrsa -out ./certs/client.key 2048

# Generate client CSR
openssl req -new -key ./certs/client.key -out ./certs/client.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=gateway-client"

# Sign client certificate with CA
openssl x509 -req -days 365 -in ./certs/client.csr -CA ./certs/ca.crt -CAkey ./certs/ca.key -CAcreateserial -out ./certs/client.crt

# Set proper permissions
chmod 600 ./certs/*.key
chmod 644 ./certs/*.crt

# Clean up CSR files
rm ./certs/server.csr ./certs/client.csr

echo "✅ SSL certificates generated successfully!"
echo ""
echo "📁 Generated files:"
echo "  - ./certs/server.key (server private key)"
echo "  - ./certs/server.crt (server certificate)"
echo "  - ./certs/client.key (client private key)"
echo "  - ./certs/client.crt (client certificate)"
echo "  - ./certs/ca.key (CA private key)"
echo "  - ./certs/ca.crt (CA certificate)"
echo ""
echo "⚠️  IMPORTANT: These are self-signed certificates for development only!"
echo "   For production, use certificates from a trusted Certificate Authority."
echo ""
echo "🚀 Your server will now start with HTTPS when you run:"
echo "   NODE_ENV=development node src/server.js" 