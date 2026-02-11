const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const oauthMigrations = [
  // OAuth Clients table
  `CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] DEFAULT '{}',
    allowed_scopes TEXT[] DEFAULT '{}',
    grant_types TEXT[] DEFAULT '{"authorization_code","refresh_token"}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // Authorization Codes table
  `CREATE TABLE IF NOT EXISTS authorization_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // Create indexes
  `CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);`,
  `CREATE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code);`,
  `CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id);`,
  `CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);`,
];

async function runOAuthMigrations() {
  const client = await pool.connect();
  
  try {
    console.log('Running OAuth2 migrations...\n');
    
    for (let i = 0; i < oauthMigrations.length; i++) {
      const migration = oauthMigrations[i];
      console.log(`Running OAuth migration ${i + 1}/${oauthMigrations.length}...`);
      await client.query(migration);
      console.log(`✓ OAuth migration ${i + 1} completed`);
    }
    
    console.log('\n✓ All OAuth2 migrations completed successfully!');
    
  } catch (error) {
    console.error('Error running OAuth migrations:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

if (require.main === module) {
  runOAuthMigrations()
    .then(() => {
      console.log('OAuth2 migration process complete!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('OAuth2 migration failed:', error);
      process.exit(1);
    });
}

module.exports = runOAuthMigrations;
