const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const migrations = [
  // Create UUID extension
  `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,
  
  // Users table
  `CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // Roles table
  `CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // Permissions table
  `CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // User_Roles junction table
  `CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
  );`,
  
  // Role_Permissions junction table
  `CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
  );`,
  
  // Refresh tokens table
  `CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // Audit logs table
  `CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(20),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );`,
  
  // Create indexes for better performance
  `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
  `CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);`,
  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);`,
  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);`,
  `CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);`,
  `CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);`,
  `CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);`,
  `CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);`,
  
  // Create updated_at trigger function
  `CREATE OR REPLACE FUNCTION update_updated_at_column()
  RETURNS TRIGGER AS $$
  BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
  END;
  $$ language 'plpgsql';`,
  
  // Add trigger to users table
  `DROP TRIGGER IF EXISTS update_users_updated_at ON users;`,
  `CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();`
];

async function runMigrations() {
  const client = await pool.connect();
  
  try {
    console.log('Running migrations...\n');
    
    for (let i = 0; i < migrations.length; i++) {
      const migration = migrations[i];
      console.log(`Running migration ${i + 1}/${migrations.length}...`);
      await client.query(migration);
      console.log(`✓ Migration ${i + 1} completed`);
    }
    
    console.log('\n✓ All migrations completed successfully!');
    
  } catch (error) {
    console.error('Error running migrations:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

runMigrations()
  .then(() => {
    console.log('Migration process complete!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Migration failed:', error);
    process.exit(1);
  });
