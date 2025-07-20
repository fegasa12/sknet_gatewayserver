#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🚀 Setting up Secure Gateway Server for Railway deployment...');

// Create necessary directories
const directories = [
  'logs',
  'temp',
  'uploads',
  'certs'
];

directories.forEach(dir => {
  const dirPath = path.join(process.cwd(), dir);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`✅ Created directory: ${dir}`);
  } else {
    console.log(`📁 Directory already exists: ${dir}`);
  }
});

// Create a basic .env file if it doesn't exist (for local development)
const envPath = path.join(process.cwd(), '.env');
if (!fs.existsSync(envPath)) {
  const envContent = `# Railway will provide these environment variables
# This file is for local development only

PORT=3000
NODE_ENV=development

# Database - Railway will provide DATABASE_URL
# Redis - Railway will provide REDIS_URL

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_here_make_it_long_and_random
JWT_REFRESH_SECRET=your_super_secret_refresh_key_here_make_it_long_and_random
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Private API Configuration
PRIVATE_API_URL=https://private-api.internal
GATEWAY_SECRET=your_gateway_secret_key

# Security Configuration
ALLOWED_ORIGINS=https://localhost:3000
SESSION_SECRET=your_session_secret_key
BCRYPT_ROUNDS=12

# File Upload Configuration
MAX_FILE_SIZE=10485760
UPLOAD_PATH=./uploads

# Logging Configuration
LOG_LEVEL=info
LOG_FILE=./logs/gateway.log

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX_REQUESTS=5

# Document Processing
TEMP_DIR=./temp
`;
  
  fs.writeFileSync(envPath, envContent);
  console.log('✅ Created .env file for local development');
} else {
  console.log('📄 .env file already exists');
}

// Create a basic log file
const logPath = path.join(process.cwd(), 'logs', 'gateway.log');
if (!fs.existsSync(logPath)) {
  fs.writeFileSync(logPath, `Gateway Server Log - Started at ${new Date().toISOString()}\n`);
  console.log('✅ Created initial log file');
}

console.log('\n🎉 Setup complete!');
console.log('\n📋 Next steps:');
console.log('1. Copy env.example to .env and configure your local environment');
console.log('2. For Railway deployment, set environment variables in Railway dashboard');
console.log('3. Run "npm start" to start the server');
console.log('\n🔧 Railway deployment notes:');
console.log('- Railway will automatically provide DATABASE_URL and REDIS_URL');
console.log('- Set JWT_SECRET, JWT_REFRESH_SECRET, and other secrets in Railway dashboard');
console.log('- The server will run on the PORT provided by Railway'); 