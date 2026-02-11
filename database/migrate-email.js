const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const emailVerificationMigrations = [
  // Email verification tokens table
  `CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // Password reset tokens table (bonus feature)
  `CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // Create indexes
  `CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_token ON email_verification_tokens(token);`,
  `CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);`,
  `CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);`,
  `CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);`,
];

async function runEmailVerificationMigrations() {
  const client = await pool.connect();
  
  try {
    console.log('Running email verification migrations...\n');
    
    for (let i = 0; i < emailVerificationMigrations.length; i++) {
      const migration = emailVerificationMigrations[i];
      console.log(`Running migration ${i + 1}/${emailVerificationMigrations.length}...`);
      await client.query(migration);
      console.log(`✓ Migration ${i + 1} completed`);
    }
    
    console.log('\n✓ All email verification migrations completed successfully!');
    
  } catch (error) {
    console.error('Error running email verification migrations:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

if (require.main === module) {
  runEmailVerificationMigrations()
    .then(() => {
      console.log('Email verification migration process complete!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Email verification migration failed:', error);
      process.exit(1);
    });
}

module.exports = runEmailVerificationMigrations;
