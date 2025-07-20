#!/usr/bin/env node

const { Pool } = require('pg');
require('dotenv').config();

async function runMigrations() {
  console.log('🔄 Running database migrations...');

  // Use Railway's DATABASE_URL or fall back to individual env vars
  const connectionString = process.env.DATABASE_URL || 
    `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`;

  const pool = new Pool({
    connectionString,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });

  try {
    // Test connection
    await pool.query('SELECT NOW()');
    console.log('✅ Database connection successful');

    // Create migrations table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Define migrations
    const migrations = [
      {
        name: '001_create_users_table',
        sql: `
          CREATE TABLE IF NOT EXISTS users (
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
          )
        `
      },
      {
        name: '002_create_sessions_table',
        sql: `
          CREATE TABLE IF NOT EXISTS sessions (
            id VARCHAR(255) PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            device_fingerprint VARCHAR(255),
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address INET,
            user_agent TEXT
          )
        `
      },
      {
        name: '003_create_document_access_logs_table',
        sql: `
          CREATE TABLE IF NOT EXISTS document_access_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            document_id VARCHAR(255) NOT NULL,
            action VARCHAR(50) NOT NULL,
            session_id VARCHAR(255),
            ip_address INET,
            user_agent TEXT,
            metadata JSONB,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `
      },
      {
        name: '004_create_security_events_table',
        sql: `
          CREATE TABLE IF NOT EXISTS security_events (
            id SERIAL PRIMARY KEY,
            event_type VARCHAR(100) NOT NULL,
            user_id INTEGER REFERENCES users(id),
            session_id VARCHAR(255),
            ip_address INET,
            user_agent TEXT,
            data JSONB,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `
      },
      {
        name: '005_create_encrypted_metadata_table',
        sql: `
          CREATE TABLE IF NOT EXISTS encrypted_metadata (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            document_id VARCHAR(255) NOT NULL,
            encrypted_data BYTEA NOT NULL,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, document_id)
          )
        `
      },
      {
        name: '006_create_indexes',
        sql: `
          CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
          CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
          CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
          CREATE INDEX IF NOT EXISTS idx_document_access_logs_user_id ON document_access_logs(user_id);
          CREATE INDEX IF NOT EXISTS idx_document_access_logs_document_id ON document_access_logs(document_id);
          CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
          CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
          CREATE INDEX IF NOT EXISTS idx_encrypted_metadata_user_document ON encrypted_metadata(user_id, document_id);
        `
      }
    ];

    // Run migrations
    for (const migration of migrations) {
      const { rows } = await pool.query(
        'SELECT id FROM migrations WHERE name = $1',
        [migration.name]
      );

      if (rows.length === 0) {
        console.log(`📝 Running migration: ${migration.name}`);
        await pool.query(migration.sql);
        await pool.query(
          'INSERT INTO migrations (name) VALUES ($1)',
          [migration.name]
        );
        console.log(`✅ Completed migration: ${migration.name}`);
      } else {
        console.log(`⏭️  Migration already applied: ${migration.name}`);
      }
    }

    console.log('\n🎉 All migrations completed successfully!');

    // Show table count
    const tableCount = await pool.query(`
      SELECT COUNT(*) as count 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    console.log(`📊 Total tables in database: ${tableCount.rows[0].count}`);

  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

// Run migrations if this file is executed directly
if (require.main === module) {
  runMigrations().catch(console.error);
}

module.exports = { runMigrations }; 