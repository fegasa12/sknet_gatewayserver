# Secure Gateway Server

A high-security gateway server for document management with multi-factor authentication, designed to sit between client applications and private APIs. This server provides secure document viewing, audit logging, and session management with enterprise-grade security features.

## 🚀 Features

### Security Features
- **Multi-Factor Authentication (MFA)**
  - TOTP (Time-based One-Time Password)
  - Biometric authentication support
  - Session-based authentication with JWT tokens
- **Document Security**
  - Server-side document processing with watermarks
  - Encrypted metadata storage
  - Secure document viewing with session validation
  - Audit logging for all document access
- **Infrastructure Security**
  - Rate limiting and DDoS protection
  - CORS configuration
  - Security headers with Helmet
  - mTLS support for private API communication

### Technical Features
- **Session Management**
  - Redis-based session storage
  - Device fingerprinting
  - Automatic session expiration
- **Database Integration**
  - PostgreSQL for audit logs and user data
  - Encrypted metadata storage
  - Comprehensive logging system
- **Document Processing**
  - PDF watermarking
  - Word document processing
  - Excel document handling
  - LibreOffice integration for conversions

## 🏗️ Architecture

```
Client App → Gateway Server → Private API
                ↓
            [Security Layer]
            - Authentication
            - Rate Limiting
            - Audit Logging
            - Document Processing
```

## 📋 Prerequisites

- Node.js 18+ 
- PostgreSQL database
- Redis (optional, for session management)
- LibreOffice (for document conversion)

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd sknet_gatewayserver
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Setup environment**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

4. **Run setup script**
   ```bash
   npm run setup
   ```

5. **Run database migrations**
   ```bash
   npm run migrate
   ```

6. **Start the server**
   ```bash
   npm run dev
   ```

### Railway Deployment

🚀 **One-Click Deploy**: [Deploy to Railway](https://railway.app/template/new?template=https://github.com/your-username/sknet_gatewayserver)

**Manual Setup**:

1. **Connect to Railway**
   ```bash
   railway login
   railway link
   ```

2. **Add PostgreSQL service**
   ```bash
   railway add
   # Select PostgreSQL
   ```

3. **Add Redis service (optional)**
   ```bash
   railway add
   # Select Redis
   ```

4. **Set environment variables**
   ```bash
   railway variables set NODE_ENV=production
   railway variables set JWT_SECRET=your_super_secret_jwt_key
   railway variables set JWT_REFRESH_SECRET=your_super_secret_refresh_key
   railway variables set GATEWAY_SECRET=your_gateway_secret
   railway variables set PRIVATE_API_URL=https://your-private-api.com
   railway variables set ALLOWED_ORIGINS=*
   ```

5. **Deploy**
   ```bash
   railway up
   ```

**✅ Railway automatically handles**:
- SSL/HTTPS certificates
- Database connection (`DATABASE_URL`)
- Redis connection (`REDIS_URL`)
- Health checks
- Auto-scaling

**📖 For detailed Railway setup**: See [docs/RAILWAY_DEPLOYMENT.md](docs/RAILWAY_DEPLOYMENT.md)

### Testing Configuration

For testing purposes, you can set `ALLOWED_ORIGINS=*` to allow all origins. This is useful for:

- **API Testing**: Tools like Postman, Insomnia, or curl
- **Frontend Development**: Any local development server
- **Mobile Apps**: Native mobile applications
- **Public Testing**: Making the API publicly accessible

**⚠️ Security Warning**: Only use `ALLOWED_ORIGINS=*` for testing. In production, specify exact domains:

```bash
# Production example
railway variables set ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PORT` | Server port | No | 3000 |
| `NODE_ENV` | Environment | No | development |
| `DATABASE_URL` | PostgreSQL connection string | Yes* | - |
| `REDIS_URL` | Redis connection string | No | - |
| `JWT_SECRET` | JWT signing secret | Yes | - |
| `JWT_REFRESH_SECRET` | JWT refresh secret | Yes | - |
| `GATEWAY_SECRET` | Gateway authentication secret | Yes | - |
| `PRIVATE_API_URL` | Private API endpoint | Yes | - |
| `ALLOWED_ORIGINS` | CORS allowed origins | No | localhost:3000 |

*Railway automatically provides `DATABASE_URL` and `REDIS_URL`

### Database Schema

The server creates the following tables:
- `users` - User accounts and authentication data
- `sessions` - Active user sessions
- `document_access_logs` - Document access audit trail
- `security_events` - Security event logging
- `encrypted_metadata` - Encrypted document metadata

## 📡 API Endpoints

### Authentication
- `POST /api/auth/primary` - Primary authentication (username/password)
- `POST /api/auth/complete` - Complete MFA authentication
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - Logout and invalidate session

### Session Management
- `GET /api/session/validate` - Validate current session
- `GET /api/session/public-key` - Get session public key

### Document Management
- `POST /api/documents/:id/secure-view` - Create secure document view
- `GET /api/documents/secure/:token` - Serve secure document

### Audit & Security
- `POST /api/audit/document-access` - Log document access
- `POST /api/security/log` - Log security events

### Health Check
- `GET /api/health` - Server health status

## 🔒 Security Considerations

### Production Deployment
1. **Use strong secrets**: Generate cryptographically secure random strings for JWT secrets
2. **Enable HTTPS**: Always use HTTPS in production
3. **Configure CORS**: Set `ALLOWED_ORIGINS` to your actual frontend domains
4. **Rate limiting**: Adjust rate limits based on your traffic patterns
5. **Audit logging**: Monitor security events and document access logs
6. **Certificate management**: Properly manage mTLS certificates for private API communication

### Security Headers
The server includes comprehensive security headers:
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection

## 🧪 Testing

### Unit Tests

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

### API Testing

With `ALLOWED_ORIGINS=*`, you can test the API from any origin:

#### Health Check
```bash
curl https://your-railway-app.railway.app/api/health
```

#### Authentication Test
```bash
# Primary authentication
curl -X POST https://your-railway-app.railway.app/api/auth/primary \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass"}'
```

#### Using Postman/Insomnia
1. Set the base URL to your Railway app URL
2. Add headers as needed
3. All endpoints will be accessible for testing

#### Frontend Testing
```javascript
// Example fetch request
fetch('https://your-railway-app.railway.app/api/health')
  .then(response => response.json())
  .then(data => console.log(data));
```

## 📊 Monitoring

The server includes built-in monitoring:
- Health check endpoint (`/api/health`)
- Comprehensive logging with Winston
- Audit trails for all document access
- Security event logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the API endpoints

## 🔄 Updates

To update the server:
1. Pull the latest changes
2. Run `npm install` to update dependencies
3. Run `npm run migrate` to apply any database changes
4. Restart the server

---

**Note**: This is a security-critical application. Always review security configurations before deploying to production. 