#!/usr/bin/env node

const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const readline = require('readline');

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Database connection
let db;

async function connectDatabase() {
  try {
    const connectionString = process.env.DATABASE_URL || 
      `postgresql://${process.env.DB_USER || 'postgres'}:${process.env.DB_PASSWORD}@${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 5432}/${process.env.DB_NAME || 'secure_docs'}`;
    
    db = new Pool({
      connectionString,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });

    // Test connection
    await db.query('SELECT NOW()');
    console.log('✅ Database connected successfully');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    return false;
  }
}

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
}

async function validateInput(input, fieldName, validators = {}) {
  const { required = true, minLength, maxLength, pattern } = validators;
  
  if (required && (!input || input.trim() === '')) {
    console.log(`❌ ${fieldName} is required`);
    return false;
  }
  
  if (minLength && input.length < minLength) {
    console.log(`❌ ${fieldName} must be at least ${minLength} characters`);
    return false;
  }
  
  if (maxLength && input.length > maxLength) {
    console.log(`❌ ${fieldName} must be no more than ${maxLength} characters`);
    return false;
  }
  
  if (pattern && !pattern.test(input)) {
    console.log(`❌ ${fieldName} format is invalid`);
    return false;
  }
  
  return true;
}

async function addUser() {
  console.log('👤 Add New User\n');
  
  try {
    // Get user input
    const username = await question('Username: ');
    if (!(await validateInput(username, 'Username', { minLength: 3, maxLength: 50 }))) {
      return false;
    }
    
    const email = await question('Email (optional): ');
    if (email && !(await validateInput(email, 'Email', { 
      required: false, 
      pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ 
    }))) {
      return false;
    }
    
    const password = await question('Password: ');
    if (!(await validateInput(password, 'Password', { minLength: 8 }))) {
      return false;
    }
    
    const confirmPassword = await question('Confirm Password: ');
    if (password !== confirmPassword) {
      console.log('❌ Passwords do not match');
      return false;
    }
    
    const enableTOTP = await question('Enable TOTP 2FA? (y/N): ');
    const enableBiometric = await question('Enable biometric authentication? (y/N): ');
    
    // Check if user already exists
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );
    
    if (existingUser.rows.length > 0) {
      console.log('❌ User already exists');
      return false;
    }
    
    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    
    // Generate TOTP secret if enabled
    let totpSecret = null;
    if (enableTOTP.toLowerCase() === 'y') {
      const speakeasy = require('speakeasy');
      totpSecret = speakeasy.generateSecret({
        name: `Gateway Server (${username})`,
        issuer: 'Secure Gateway'
      }).base32;
    }
    
    // Insert user
    const result = await db.query(
      `INSERT INTO users (username, email, password_hash, totp_secret, biometric_credentials, created_at) 
       VALUES ($1, $2, $3, $4, $5, NOW()) 
       RETURNING id, username, email, created_at`,
      [
        username,
        email || null,
        passwordHash,
        totpSecret,
        enableBiometric.toLowerCase() === 'y' ? '[]' : '[]'
      ]
    );
    
    const user = result.rows[0];
    
    console.log('\n✅ User created successfully!');
    console.log(`📋 User Details:`);
    console.log(`   ID: ${user.id}`);
    console.log(`   Username: ${user.username}`);
    console.log(`   Email: ${user.email || 'Not set'}`);
    console.log(`   Created: ${user.created_at}`);
    console.log(`   TOTP 2FA: ${totpSecret ? 'Enabled' : 'Disabled'}`);
    console.log(`   Biometric: ${enableBiometric.toLowerCase() === 'y' ? 'Enabled' : 'Disabled'}`);
    
    if (totpSecret) {
      console.log('\n🔐 TOTP Setup:');
      console.log(`   Secret: ${totpSecret}`);
      console.log('   QR Code URL: https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Gateway%20Server%20(' + username + ')?secret=' + totpSecret + '&issuer=Secure%20Gateway');
      console.log('\n💡 Use Google Authenticator, Authy, or any TOTP app to scan the QR code');
    }
    
    return true;
    
  } catch (error) {
    console.error('❌ Error creating user:', error.message);
    return false;
  }
}

async function listUsers() {
  try {
    const result = await db.query(
      'SELECT id, username, email, created_at, last_login, failed_attempts FROM users ORDER BY created_at DESC'
    );
    
    if (result.rows.length === 0) {
      console.log('📭 No users found');
      return;
    }
    
    console.log('\n👥 Users in Database:');
    console.log('─'.repeat(80));
    console.log('ID  | Username          | Email               | Created           | Last Login        | Failed Attempts');
    console.log('─'.repeat(80));
    
    result.rows.forEach(user => {
      const id = user.id.toString().padEnd(3);
      const username = (user.username || '').padEnd(16);
      const email = (user.email || 'Not set').padEnd(19);
      const created = user.created_at ? user.created_at.toISOString().split('T')[0] : 'N/A';
      const lastLogin = user.last_login ? user.last_login.toISOString().split('T')[0] : 'Never';
      const failedAttempts = user.failed_attempts || 0;
      
      console.log(`${id} | ${username} | ${email} | ${created} | ${lastLogin} | ${failedAttempts}`);
    });
    
  } catch (error) {
    console.error('❌ Error listing users:', error.message);
  }
}

async function main() {
  console.log('🔐 Secure Gateway Server - User Management\n');
  
  // Connect to database
  const connected = await connectDatabase();
  if (!connected) {
    console.log('💡 Make sure your database is running and environment variables are set');
    console.log('   For Railway: DATABASE_URL is automatically provided');
    console.log('   For local: Set DB_HOST, DB_USER, DB_PASSWORD, etc.');
    process.exit(1);
  }
  
  // Show menu
  while (true) {
    console.log('\n📋 User Management Menu:');
    console.log('1. Add new user');
    console.log('2. List all users');
    console.log('3. Exit');
    
    const choice = await question('\nSelect option (1-3): ');
    
    switch (choice) {
      case '1':
        await addUser();
        break;
      case '2':
        await listUsers();
        break;
      case '3':
        console.log('👋 Goodbye!');
        process.exit(0);
      default:
        console.log('❌ Invalid option. Please select 1, 2, or 3.');
    }
  }
}

// Handle cleanup
process.on('SIGINT', () => {
  console.log('\n👋 Goodbye!');
  if (db) db.end();
  rl.close();
  process.exit(0);
});

// Run the script
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { addUser, listUsers }; 