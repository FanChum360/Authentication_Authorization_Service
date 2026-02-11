const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  database: 'postgres', // Connect to default database first
});

async function setupDatabase() {
  const client = await pool.connect();
  
  try {
    console.log('Setting up database...');
    
    // Check if database exists
    const dbCheck = await client.query(
      "SELECT 1 FROM pg_database WHERE datname = $1",
      [process.env.DB_NAME]
    );
    
    if (dbCheck.rows.length === 0) {
      // Create database
      await client.query(`CREATE DATABASE ${process.env.DB_NAME}`);
      console.log(`✓ Database '${process.env.DB_NAME}' created successfully`);
    } else {
      console.log(`✓ Database '${process.env.DB_NAME}' already exists`);
    }
    
  } catch (error) {
    console.error('Error setting up database:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

setupDatabase()
  .then(() => {
    console.log('Database setup complete!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Database setup failed:', error);
    process.exit(1);
  });
