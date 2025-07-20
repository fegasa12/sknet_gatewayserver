// Gateway Server Implementation (Node.js/Express)
// This server sits between your client app and the private API

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require('multer');
const Redis = require('redis');
const { Pool } = require('pg');
const speakeasy = require('speakeasy');
const nodemailer = require('nodemailer');
const https = require('https');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const PDFDocument = require('pdfkit');
const libre = require('libreoffice-convert');
const sharp = require('sharp');

class GatewayServer {
  constructor() {
    this.app = express();
    this.redis = null;
    this.db = null;
    this.privateApiClient = null;
    this.sessionStore = new Map();
    this.activeDocumentSessions = new Map();
    
    this.setupMiddleware();
    this.setupRoutes();
    this.setupPrivateApiConnection();
  }

  async initialize() {
    // Initialize Redis for session management
    // Use Railway's REDIS_URL or fall back to individual env vars
    const redisUrl = process.env.REDIS_URL || 
      `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`;
    
    this.redis = Redis.createClient({
      url: redisUrl,
      password: process.env.REDIS_PASSWORD
    });
    
    try {
      await this.redis.connect();
      console.log('✅ Redis connected successfully');
    } catch (error) {
      console.warn('⚠️  Redis connection failed, continuing without Redis:', error.message);
      this.redis = null;
    }

    // Initialize PostgreSQL for audit logs
    // Use Railway's DATABASE_URL or fall back to individual env vars
    const connectionString = process.env.DATABASE_URL || 
      `postgresql://${process.env.DB_USER || 'postgres'}:${process.env.DB_PASSWORD}@${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 5432}/${process.env.DB_NAME || 'secure_docs'}`;
    
    this.db = new Pool({
      connectionString,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });

    try {
      // Test database connection
      await this.db.query('SELECT NOW()');
      console.log('✅ Database connected successfully');

      // Setup database tables if they don't exist
      await this.setupDatabase();
    } catch (error) {
      if (process.env.NODE_ENV === 'development') {
        console.warn('⚠️  Database connection failed in development mode, continuing without database:', error.message);
        console.warn('💡 To use database features, start PostgreSQL locally or set DATABASE_URL');
        this.db = null;
      } else {
        console.error('❌ Database connection failed:', error.message);
        throw error;
      }
    }
  }

  setupMiddleware() {
    // Security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"]
        }
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

    // CORS configuration
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['https://localhost:3000'];
    
    // Handle wildcard origin for testing
    const corsOptions = {
      origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        // Check if wildcard is enabled
        if (allowedOrigins.includes('*')) {
          return callback(null, true);
        }
        
        // Check if origin is in allowed list
        if (allowedOrigins.indexOf(origin) !== -1) {
          return callback(null, true);
        }
        
        callback(new Error('Not allowed by CORS'));
      },
      credentials: true,
      optionsSuccessStatus: 200
    };
    
    this.app.use(cors(corsOptions));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP'
    });
    this.app.use(limiter);

    // Stricter rate limiting for auth endpoints
    const authLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 5, // 5 auth attempts per 15 minutes
      skipSuccessfulRequests: true
    });
    this.app.use('/api/auth', authLimiter);

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));
  }

  setupRoutes() {
    // Authentication routes
    this.app.post('/api/auth/primary', this.handlePrimaryAuth.bind(this));
    this.app.post('/api/auth/complete', this.handleCompleteAuth.bind(this));
    this.app.post('/api/auth/biometric/register', this.handleBiometricRegister.bind(this));
    this.app.get('/api/auth/biometric/challenge', this.handleBiometricChallenge.bind(this));
    this.app.post('/api/auth/biometric/verify', this.handleBiometricVerify.bind(this));
    this.app.post('/api/auth/refresh', this.handleTokenRefresh.bind(this));
    this.app.post('/api/auth/logout', this.handleLogout.bind(this));

    // Session management
    this.app.get('/api/session/validate', this.validateSession.bind(this));
    this.app.get('/api/session/public-key', this.getSessionPublicKey.bind(this));

    // Encrypted metadata routes
    this.app.get('/api/metadata/encrypted', this.authenticateToken, this.getEncryptedMetadata.bind(this));
    this.app.post('/api/metadata/update', this.authenticateToken, this.updateEncryptedMetadata.bind(this));

    // Document routes (server-side processing)
    this.app.post('/api/documents/:id/secure-view', this.authenticateToken, this.createSecureDocumentView.bind(this));
    this.app.get('/api/documents/secure/:token', this.serveSecureDocument.bind(this));

    // Audit and security routes
    this.app.post('/api/audit/document-access', this.authenticateToken, this.logDocumentAccess.bind(this));
    this.app.post('/api/security/log', this.authenticateToken, this.logSecurityEvent.bind(this));

    // User management
    this.app.post('/api/user/public-key', this.authenticateToken, this.storeUserPublicKey.bind(this));
    this.app.get('/api/user/profile', this.authenticateToken, this.getUserProfile.bind(this));

    // Health check
    this.app.get('/api/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });
  }

  setupPrivateApiConnection() {
    // Configure axios client for private API with mTLS
    const config = {
      baseURL: process.env.PRIVATE_API_URL || 'https://private-api.internal',
      timeout: 30000
    };

    // Add mTLS configuration if certificates are available
    try {
      const certPath = process.env.CLIENT_CERT_PATH || './certs/client.crt';
      const keyPath = process.env.CLIENT_KEY_PATH || './certs/client.key';
      const caPath = process.env.CA_CERT_PATH || './certs/ca.crt';

      if (fs.existsSync(certPath) && fs.existsSync(keyPath) && fs.existsSync(caPath)) {
        config.httpsAgent = new https.Agent({
          cert: fs.readFileSync(certPath),
          key: fs.readFileSync(keyPath),
          ca: fs.readFileSync(caPath),
          rejectUnauthorized: true
        });
        console.log('✅ mTLS certificates loaded for private API');
      } else {
        console.warn('⚠️  mTLS certificates not found, private API connection may fail');
      }
    } catch (error) {
      console.warn('⚠️  Failed to load mTLS certificates:', error.message);
    }

    this.privateApiClient = axios.create(config);

    // Add request interceptor for private API authentication
    this.privateApiClient.interceptors.request.use((config) => {
      config.headers['X-Gateway-Token'] = process.env.GATEWAY_SECRET || 'dev-gateway-secret-change-in-production';
      config.headers['X-Request-ID'] = crypto.randomUUID();
      return config;
    });
  }

  async setupDatabase() {
    const tables = [
      `CREATE TABLE IF NOT EXISTS users (
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
      )`,
      
      `CREATE TABLE IF NOT EXISTS sessions (
        id VARCHAR(255) PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        device_fingerprint VARCHAR(255),
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address INET,
        user_agent TEXT
      )`,
      
      `CREATE TABLE IF NOT EXISTS document_access_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        document_id VARCHAR(255) NOT NULL,
        action VARCHAR(50) NOT NULL,
        session_id VARCHAR(255),
        ip_address INET,
        user_agent TEXT,
        metadata JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,
      
      `CREATE TABLE IF NOT EXISTS security_events (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(100) NOT NULL,
        user_id INTEGER REFERENCES users(id),
        session_id VARCHAR(255),
        ip_address INET,
        user_agent TEXT,
        data JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,
      
      `CREATE TABLE IF NOT EXISTS encrypted_metadata (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        document_id VARCHAR(255) NOT NULL,
        encrypted_data BYTEA NOT NULL,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, document_id)
      )`
    ];

    for (const table of tables) {
      await this.db.query(table);
    }

    console.log('Database tables initialized');
  }

  // Authentication handlers
  async handlePrimaryAuth(req, res) {
    try {
      const { username, password } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
      }

      // Check if database is available
      if (!this.db) {
        return res.status(503).json({ error: 'Database not available' });
      }

      // Get user from database
      const userQuery = await this.db.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      );

      if (userQuery.rows.length === 0) {
        await this.logSecurityEventInternal('failed_login', null, req, {
          reason: 'user_not_found',
          username
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = userQuery.rows[0];

      // Check if account is locked
      if (user.locked_until && new Date() < user.locked_until) {
        return res.status(423).json({ 
          error: 'Account locked',
          lockedUntil: user.locked_until
        });
      }

      // Verify password
      const passwordValid = await bcrypt.compare(password, user.password_hash);
      if (!passwordValid) {
        // Increment failed attempts
        await this.db.query(
          'UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = CASE WHEN failed_attempts >= 4 THEN NOW() + INTERVAL \'30 minutes\' ELSE locked_until END WHERE id = $1',
          [user.id]
        );

        await this.logSecurityEventInternal('failed_login', user.id, req, {
          reason: 'invalid_password'
        });

        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Reset failed attempts on successful password verification
      await this.db.query(
        'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1',
        [user.id]
      );

      // Generate challenge ID for MFA
      const challengeId = crypto.randomUUID();
      const challengeData = JSON.stringify({
        userId: user.id,
        username: user.username,
        step: 'mfa_required'
      });
      
      if (this.redis) {
        await this.redis.setEx(`challenge:${challengeId}`, 300, challengeData);
      } else {
        // Fallback to session store if Redis is not available
        this.sessionStore.set(`challenge:${challengeId}`, challengeData);
      }

      res.json({
        challengeId,
        otpRequired: !!user.totp_secret,
        biometricAvailable: user.biometric_credentials.length > 0,
        message: 'Primary authentication successful'
      });

    } catch (error) {
      console.error('Primary auth error:', error);
      res.status(500).json({ error: 'Authentication failed' });
    }
  }

  async handleCompleteAuth(req, res) {
    try {
      const { challengeId, secondFactor, deviceFingerprint } = req.body;

      // Check if database is available
      if (!this.db) {
        return res.status(503).json({ error: 'Database not available' });
      }

      // Get challenge data
      let challengeData;
      if (this.redis) {
        challengeData = await this.redis.get(`challenge:${challengeId}`);
      } else {
        // Fallback to session store if Redis is not available
        challengeData = this.sessionStore.get(`challenge:${challengeId}`);
      }
      
      if (!challengeData) {
        return res.status(400).json({ error: 'Invalid or expired challenge' });
      }

      const challenge = typeof challengeData === 'string' ? JSON.parse(challengeData) : challengeData;
      const user = await this.db.query('SELECT * FROM users WHERE id = $1', [challenge.userId]);
      
      if (user.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const userData = user.rows[0];

      // Verify second factor (OTP or biometric)
      let mfaValid = false;
      
      if (secondFactor.type === 'otp' && userData.totp_secret) {
        mfaValid = speakeasy.totp.verify({
          secret: userData.totp_secret,
          encoding: 'base32',
          token: secondFactor.value,
          window: 2
        });
      } else if (secondFactor.type === 'biometric') {
        // Biometric verification would be handled separately
        mfaValid = secondFactor.verified === true;
      }

      if (!mfaValid) {
        await this.logSecurityEventInternal('failed_mfa', userData.id, req, {
          type: secondFactor.type
        });
        return res.status(401).json({ error: 'Invalid second factor' });
      }

      // Generate session tokens
      const sessionId = crypto.randomUUID();
      const accessToken = jwt.sign(
        { 
          userId: userData.id, 
          username: userData.username,
          sessionId 
        },
        process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production',
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { 
          userId: userData.id, 
          sessionId,
          type: 'refresh' 
        },
        process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-change-in-production',
        { expiresIn: '7d' }
      );

      // Store session in database
      await this.db.query(
        'INSERT INTO sessions (id, user_id, device_fingerprint, expires_at, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5, $6)',
        [
          sessionId,
          userData.id,
          deviceFingerprint,
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          req.ip,
          req.get('User-Agent')
        ]
      );

      // Update last login
      await this.db.query(
        'UPDATE users SET last_login = NOW() WHERE id = $1',
        [userData.id]
      );

      // Clean up challenge
      if (this.redis) {
        await this.redis.del(`challenge:${challengeId}`);
      } else {
        this.sessionStore.delete(`challenge:${challengeId}`);
      }

      // Log successful login
      await this.logSecurityEventInternal('successful_login', userData.id, req, {
        sessionId,
        deviceFingerprint
      });

      res.json({
        success: true,
        accessToken,
        refreshToken,
        sessionId,
        expiresIn: 900, // 15 minutes
        userKey: this.generateUserKey(userData.id, userData.username)
      });

    } catch (error) {
      console.error('Complete auth error:', error);
      res.status(500).json({ error: 'Authentication failed' });
    }
  }

  // Document handling
  async createSecureDocumentView(req, res) {
    try {
      const { id: documentId } = req.params;
      const { requestId, timestamp } = req.body;
      const userId = req.user.userId;

      // Check if user has access to document through private API
      const accessCheck = await this.privateApiClient.get(`/documents/${documentId}/access`, {
        headers: { 'X-User-ID': userId }
      });

      if (!accessCheck.data.hasAccess) {
        await this.logDocumentAccessInternal(userId, documentId, 'access_denied', req);
        return res.status(403).json({ error: 'Access denied' });
      }

      // Generate secure viewing token
      const viewToken = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

      // Store document session
      this.activeDocumentSessions.set(viewToken, {
        documentId,
        userId,
        expiresAt,
        requestId,
        ipAddress: req.ip
      });

      // Get document metadata from private API
      const docMetadata = await this.privateApiClient.get(`/documents/${documentId}/metadata`);
      
      // Generate watermark text
      const watermarkText = `${req.user.username} - ${new Date().toLocaleString()}`;

      res.json({
        secureUrl: `/api/documents/secure/${viewToken}`,
        expiresAt: expiresAt.toISOString(),
        watermark: watermarkText,
        metadata: {
          title: docMetadata.data.title,
          type: docMetadata.data.type,
          size: docMetadata.data.size
        }
      });

      // Log document access request
      await this.logDocumentAccessInternal(userId, documentId, 'view_requested', req, {
        requestId,
        expiresAt
      });

    } catch (error) {
      console.error('Document view creation error:', error);
      res.status(500).json({ error: 'Failed to create secure document view' });
    }
  }

  async serveSecureDocument(req, res) {
    try {
      const { token } = req.params;

      // Get document session
      const session = this.activeDocumentSessions.get(token);
      if (!session || new Date() > session.expiresAt) {
        this.activeDocumentSessions.delete(token);
        return res.status(404).json({ error: 'Document not found or expired' });
      }

      // Get document from private API
      const docResponse = await this.privateApiClient.get(
        `/documents/${session.documentId}/content`,
        { responseType: 'stream' }
      );

      // Set security headers
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');

      // Determine content type and process accordingly
      const contentType = docResponse.headers['content-type'];
      
      if (contentType?.includes('pdf')) {
        await this.servePDFWithWatermark(docResponse.data, res, session);
      } else if (contentType?.includes('word') || contentType?.includes('document')) {
        await this.serveWordDocument(docResponse.data, res, session);
      } else if (contentType?.includes('excel') || contentType?.includes('spreadsheet')) {
        await this.serveExcelDocument(docResponse.data, res, session);
      } else {
        // Default: serve as-is with security headers
        res.setHeader('Content-Type', contentType || 'application/octet-stream');
        docResponse.data.pipe(res);
      }

      // Log document view
      await this.logDocumentAccessInternal(session.userId, session.documentId, 'viewed', {
        ip: session.ipAddress
      });

    } catch (error) {
      console.error('Secure document serve error:', error);
      res.status(500).json({ error: 'Failed to serve document' });
    }
  }

  async servePDFWithWatermark(pdfStream, res, session) {
    // For production, you would use a library like PDF-lib to add watermarks
    // This is a simplified version
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline');
    
    // In a real implementation, you would:
    // 1. Load the PDF
    // 2. Add watermark to each page
    // 3. Stream the modified PDF
    pdfStream.pipe(res);
  }

  async serveWordDocument(docStream, res, session) {
    // Convert Word document to HTML for secure viewing
    try {
      const chunks = [];
      docStream.on('data', chunk => chunks.push(chunk));
      docStream.on('end', async () => {
        const buffer = Buffer.concat(chunks);
        
        // Convert to HTML using libreoffice
        libre.convert(buffer, '.html', undefined, (err, done) => {
          if (err) {
            console.error('Word conversion error:', err);
            return res.status(500).json({ error: 'Conversion failed' });
          }
          
          res.setHeader('Content-Type', 'text/html');
          res.send(this.addSecurityToHTML(done.toString(), session));
        });
      });
    } catch (error) {
      console.error('Word document serve error:', error);
      res.status(500).json({ error: 'Failed to serve Word document' });
    }
  }

  async serveExcelDocument(excelStream, res, session) {
    // Convert Excel to HTML table for secure viewing
    try {
      const chunks = [];
      excelStream.on('data', chunk => chunks.push(chunk));
      excelStream.on('end', async () => {
        const buffer = Buffer.concat(chunks);
        
        // Convert to HTML using libreoffice
        libre.convert(buffer, '.html', undefined, (err, done) => {
          if (err) {
            console.error('Excel conversion error:', err);
            return res.status(500).json({ error: 'Conversion failed' });
          }
          
          res.setHeader('Content-Type', 'text/html');
          res.send(this.addSecurityToHTML(done.toString(), session));
        });
      });
    } catch (error) {
      console.error('Excel document serve error:', error);
      res.status(500).json({ error: 'Failed to serve Excel document' });
    }
  }

  addSecurityToHTML(html, session) {
    const watermarkText = `User: ${session.userId} - ${new Date().toLocaleString()}`;
    
    const secureHTML = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            position: relative;
            font-family: Arial, sans-serif;
            -webkit-user-select: none;
            -moz-user-select: none;
            user-select: none;
        }
        .watermark {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-45deg);
            font-size: 48px;
            color: rgba(0, 0, 0, 0.1);
            pointer-events: none;
            z-index: 1000;
            user-select: none;
        }
        @media print {
            .watermark { display: block !important; }
        }
    </style>
    <script>
        // Disable right-click
        document.addEventListener('contextmenu', e => e.preventDefault());
        
        // Disable F12, Ctrl+Shift+I, etc.
        document.addEventListener('keydown', e => {
            if (e.key === 'F12' || 
                (e.ctrlKey && e.shiftKey && e.key === 'I') ||
                (e.ctrlKey && e.shiftKey && e.key === 'C') ||
                (e.ctrlKey && e.key === 'u')) {
                e.preventDefault();
                return false;
            }
        });
        
        // Disable printing
        window.addEventListener('beforeprint', e => {
            e.preventDefault();
            return false;
        });
    </script>
</head>
<body>
    <div class="watermark">${watermarkText}</div>
    ${html}
</body>
</html>`;
    
    return secureHTML;
  }

  // Middleware
  authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production', (err, user) => {
      if (err) {
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(403).json({ error: 'Invalid token' });
      }

      req.user = user;
      next();
    });
  }

  // Utility methods
  generateUserKey(userId, username) {
    return crypto
      .createHmac('sha256', process.env.USER_KEY_SECRET || 'dev-user-key-secret-change-in-production')
      .update(`${userId}:${username}`)
      .digest('hex');
  }

  async logDocumentAccessInternal(userId, documentId, action, req, metadata = {}) {
    try {
      if (!this.db) {
        console.warn('Database not available, skipping document access log');
        return;
      }
      
      await this.db.query(
        'INSERT INTO document_access_logs (user_id, document_id, action, session_id, ip_address, user_agent, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [
          userId,
          documentId,
          action,
          req.user?.sessionId || null,
          req.ip,
          req.get('User-Agent'),
          JSON.stringify(metadata)
        ]
      );
    } catch (error) {
      console.error('Failed to log document access:', error);
    }
  }

  async logSecurityEventInternal(eventType, userId, req, data = {}) {
    try {
      if (!this.db) {
        console.warn('Database not available, skipping security event log');
        return;
      }
      
      await this.db.query(
        'INSERT INTO security_events (event_type, user_id, session_id, ip_address, user_agent, data) VALUES ($1, $2, $3, $4, $5, $6)',
        [
          eventType,
          userId,
          req.user?.sessionId || null,
          req.ip,
          req.get('User-Agent'),
          JSON.stringify(data)
        ]
      );
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }

  // Additional route handlers would go here...
  async getEncryptedMetadata(req, res) {
    // Implementation for encrypted metadata retrieval
    res.json({ message: 'Encrypted metadata endpoint' });
  }

  async handleTokenRefresh(req, res) {
    // Implementation for token refresh
    res.json({ message: 'Token refresh endpoint' });
  }

  // Missing route handlers
  async handleBiometricRegister(req, res) {
    try {
      const { userId, biometricData } = req.body;
      
      if (!userId || !biometricData) {
        return res.status(400).json({ error: 'User ID and biometric data required' });
      }

      // Check if database is available
      if (!this.db) {
        return res.status(503).json({ error: 'Database not available' });
      }

      // Store biometric credentials
      await this.db.query(
        'UPDATE users SET biometric_credentials = $1 WHERE id = $2',
        [JSON.stringify(biometricData), userId]
      );

      res.json({ message: 'Biometric credentials registered successfully' });
    } catch (error) {
      console.error('Biometric registration error:', error);
      res.status(500).json({ error: 'Failed to register biometric credentials' });
    }
  }

  async handleBiometricChallenge(req, res) {
    try {
      const { userId } = req.query;
      
      if (!userId) {
        return res.status(400).json({ error: 'User ID required' });
      }

      // Generate challenge for biometric authentication
      const challenge = crypto.randomBytes(32).toString('hex');
      
      // Store challenge temporarily
      if (this.redis) {
        await this.redis.set(`challenge:${userId}`, challenge, 'EX', 300); // 5 minutes expiry
      } else {
        this.sessionStore.set(`challenge:${userId}`, challenge);
      }

      res.json({ challenge });
    } catch (error) {
      console.error('Biometric challenge error:', error);
      res.status(500).json({ error: 'Failed to generate challenge' });
    }
  }

  async handleBiometricVerify(req, res) {
    try {
      const { userId, signature, challenge } = req.body;
      
      if (!userId || !signature || !challenge) {
        return res.status(400).json({ error: 'User ID, signature, and challenge required' });
      }

      // Verify the stored challenge
      let storedChallenge;
      if (this.redis) {
        storedChallenge = await this.redis.get(`challenge:${userId}`);
      } else {
        storedChallenge = this.sessionStore.get(`challenge:${userId}`);
      }
      
      if (!storedChallenge || storedChallenge !== challenge) {
        return res.status(400).json({ error: 'Invalid challenge' });
      }

      // Verify biometric signature (implement your verification logic here)
      // This is a placeholder - implement actual biometric verification
      const isValid = true; // Replace with actual verification

      if (isValid) {
        // Clear the challenge
        if (this.redis) {
          await this.redis.del(`challenge:${userId}`);
        } else {
          this.sessionStore.delete(`challenge:${userId}`);
        }
        
        // Generate session token
        const token = jwt.sign(
          { userId, type: 'biometric' },
          process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production',
          { expiresIn: '1h' }
        );

        res.json({ token, message: 'Biometric authentication successful' });
      } else {
        res.status(401).json({ error: 'Biometric verification failed' });
      }
    } catch (error) {
      console.error('Biometric verification error:', error);
      res.status(500).json({ error: 'Failed to verify biometric credentials' });
    }
  }

  async handleLogout(req, res) {
    try {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      if (token) {
        // In a real implementation, you might want to blacklist the token
        // For now, we'll just return success
        await this.logSecurityEventInternal('logout', req.user?.userId, req);
      }

      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({ error: 'Failed to logout' });
    }
  }

  async validateSession(req, res) {
    try {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production', (err, decoded) => {
        if (err) {
          return res.status(401).json({ error: 'Invalid token' });
        }

        res.json({ 
          valid: true, 
          user: decoded,
          expiresAt: new Date(decoded.exp * 1000)
        });
      });
    } catch (error) {
      console.error('Session validation error:', error);
      res.status(500).json({ error: 'Failed to validate session' });
    }
  }

  async getSessionPublicKey(req, res) {
    try {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production', (err, decoded) => {
        if (err) {
          return res.status(401).json({ error: 'Invalid token' });
        }

        // Return the public key for this session
        res.json({ 
          publicKey: process.env.SESSION_PUBLIC_KEY || 'default-public-key'
        });
      });
    } catch (error) {
      console.error('Get session public key error:', error);
      res.status(500).json({ error: 'Failed to get session public key' });
    }
  }

  async updateEncryptedMetadata(req, res) {
    try {
      const { documentId, encryptedData } = req.body;
      const userId = req.user.userId;

      if (!documentId || !encryptedData) {
        return res.status(400).json({ error: 'Document ID and encrypted data required' });
      }

      // Check if database is available
      if (!this.db) {
        return res.status(503).json({ error: 'Database not available' });
      }

      // Update or insert encrypted metadata
      await this.db.query(
        `INSERT INTO encrypted_metadata (user_id, document_id, encrypted_data) 
         VALUES ($1, $2, $3) 
         ON CONFLICT (user_id, document_id) 
         DO UPDATE SET encrypted_data = $3, last_updated = CURRENT_TIMESTAMP`,
        [userId, documentId, encryptedData]
      );

      res.json({ message: 'Encrypted metadata updated successfully' });
    } catch (error) {
      console.error('Update encrypted metadata error:', error);
      res.status(500).json({ error: 'Failed to update encrypted metadata' });
    }
  }

  async logDocumentAccess(req, res) {
    try {
      const { documentId, action, metadata } = req.body;
      const userId = req.user.userId;

      await this.logDocumentAccessInternal(userId, documentId, action, req, metadata);
      res.json({ message: 'Document access logged successfully' });
    } catch (error) {
      console.error('Log document access error:', error);
      res.status(500).json({ error: 'Failed to log document access' });
    }
  }

  async logSecurityEvent(req, res) {
    try {
      const { eventType, data } = req.body;
      const userId = req.user.userId;

      await this.logSecurityEventInternal(eventType, userId, req, data);
      res.json({ message: 'Security event logged successfully' });
    } catch (error) {
      console.error('Log security event error:', error);
      res.status(500).json({ error: 'Failed to log security event' });
    }
  }

  async storeUserPublicKey(req, res) {
    try {
      const { publicKey } = req.body;
      const userId = req.user.userId;

      if (!publicKey) {
        return res.status(400).json({ error: 'Public key required' });
      }

      // Check if database is available
      if (!this.db) {
        return res.status(503).json({ error: 'Database not available' });
      }

      await this.db.query(
        'UPDATE users SET public_key = $1 WHERE id = $2',
        [publicKey, userId]
      );

      res.json({ message: 'Public key stored successfully' });
    } catch (error) {
      console.error('Store user public key error:', error);
      res.status(500).json({ error: 'Failed to store public key' });
    }
  }

  async getUserProfile(req, res) {
    try {
      const userId = req.user.userId;

      // Check if database is available
      if (!this.db) {
        return res.status(503).json({ error: 'Database not available' });
      }

      const result = await this.db.query(
        'SELECT id, username, email, created_at, last_login FROM users WHERE id = $1',
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({ user: result.rows[0] });
    } catch (error) {
      console.error('Get user profile error:', error);
      res.status(500).json({ error: 'Failed to get user profile' });
    }
  }

  // ... other route handlers
}

// Server startup
async function startServer() {
  const gateway = new GatewayServer();
  await gateway.initialize();

  const port = process.env.PORT || 3001;
  
  // Check if we're in a cloud environment (Railway, Heroku, etc.)
  const isCloudEnvironment = process.env.RAILWAY_ENVIRONMENT || 
                            process.env.HEROKU_APP_NAME || 
                            process.env.VERCEL_URL ||
                            process.env.NODE_ENV === 'production';
  
  if (isCloudEnvironment) {
    // Cloud platforms handle SSL termination, use HTTP server
    console.log('☁️  Detected cloud environment, using HTTP server (SSL handled by platform)');
    const http = require('http');
    http.createServer(gateway.app).listen(port, () => {
      console.log(`🚀 Gateway Server running on port ${port} (HTTPS handled by platform)`);
    });
  } else {
    // Local development - check for SSL certificates
    const sslKeyPath = process.env.SSL_KEY_PATH || './certs/server.key';
    const sslCertPath = process.env.SSL_CERT_PATH || './certs/server.crt';
    
    try {
      // Try to read SSL certificates
      const httpsOptions = {
        key: fs.readFileSync(sslKeyPath),
        cert: fs.readFileSync(sslCertPath)
      };

      https.createServer(httpsOptions, gateway.app).listen(port, () => {
        console.log(`🔒 Secure Gateway Server running on https://localhost:${port}`);
      });
    } catch (error) {
      if (error.code === 'ENOENT') {
        console.warn('⚠️  SSL certificates not found, starting HTTP server for development');
        console.warn('💡 To enable HTTPS, run: npm run certs');
        
        // Fall back to HTTP server
        const http = require('http');
        http.createServer(gateway.app).listen(port, () => {
          console.log(`🌐 Gateway Server running on http://localhost:${port}`);
        });
      } else {
        console.error('❌ Failed to start server:', error.message);
        throw error;
      }
    }
  }
}

// Error handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

if (require.main === module) {
  startServer().catch(console.error);
}

module.exports = { GatewayServer };