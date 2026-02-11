const { Pool } = require('pg');
const bcrypt = require('bcrypt');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

async function seedDatabase() {
  const client = await pool.connect();
  
  try {
    console.log('Seeding database...\n');
    
    // Insert default roles
    console.log('Creating roles...');
    const roles = [
      { name: 'admin', description: 'Administrator with full access' },
      { name: 'user', description: 'Standard user with basic access' },
      { name: 'moderator', description: 'Moderator with elevated permissions' }
    ];
    
    const roleIds = {};
    for (const role of roles) {
      const result = await client.query(
        `INSERT INTO roles (name, description) 
         VALUES ($1, $2) 
         ON CONFLICT (name) DO UPDATE SET description = $2
         RETURNING id, name`,
        [role.name, role.description]
      );
      roleIds[role.name] = result.rows[0].id;
      console.log(`✓ Role '${role.name}' created`);
    }
    
    // Insert permissions
    console.log('\nCreating permissions...');
    const permissions = [
      // User permissions
      { name: 'users:read', resource: 'users', action: 'read', description: 'View user information' },
      { name: 'users:write', resource: 'users', action: 'write', description: 'Create and update users' },
      { name: 'users:delete', resource: 'users', action: 'delete', description: 'Delete users' },
      
      // Role permissions
      { name: 'roles:read', resource: 'roles', action: 'read', description: 'View roles' },
      { name: 'roles:write', resource: 'roles', action: 'write', description: 'Create and update roles' },
      { name: 'roles:delete', resource: 'roles', action: 'delete', description: 'Delete roles' },
      
      // Permission permissions
      { name: 'permissions:read', resource: 'permissions', action: 'read', description: 'View permissions' },
      { name: 'permissions:write', resource: 'permissions', action: 'write', description: 'Manage permissions' },
      
      // Profile permissions
      { name: 'profile:read', resource: 'profile', action: 'read', description: 'View own profile' },
      { name: 'profile:write', resource: 'profile', action: 'write', description: 'Update own profile' },
      
      // Audit permissions
      { name: 'audit:read', resource: 'audit', action: 'read', description: 'View audit logs' }
    ];
    
    const permissionIds = {};
    for (const perm of permissions) {
      const result = await client.query(
        `INSERT INTO permissions (name, resource, action, description) 
         VALUES ($1, $2, $3, $4) 
         ON CONFLICT (name) DO UPDATE SET description = $4
         RETURNING id, name`,
        [perm.name, perm.resource, perm.action, perm.description]
      );
      permissionIds[perm.name] = result.rows[0].id;
      console.log(`✓ Permission '${perm.name}' created`);
    }
    
    // Assign permissions to roles
    console.log('\nAssigning permissions to roles...');
    
    // Admin gets all permissions
    const adminPermissions = Object.values(permissionIds);
    for (const permId of adminPermissions) {
      await client.query(
        `INSERT INTO role_permissions (role_id, permission_id) 
         VALUES ($1, $2) 
         ON CONFLICT DO NOTHING`,
        [roleIds.admin, permId]
      );
    }
    console.log(`✓ Assigned ${adminPermissions.length} permissions to admin role`);
    
    // User gets basic permissions
    const userPermissions = [
      permissionIds['profile:read'],
      permissionIds['profile:write']
    ];
    for (const permId of userPermissions) {
      await client.query(
        `INSERT INTO role_permissions (role_id, permission_id) 
         VALUES ($1, $2) 
         ON CONFLICT DO NOTHING`,
        [roleIds.user, permId]
      );
    }
    console.log(`✓ Assigned ${userPermissions.length} permissions to user role`);
    
    // Moderator gets moderate permissions
    const moderatorPermissions = [
      permissionIds['profile:read'],
      permissionIds['profile:write'],
      permissionIds['users:read'],
      permissionIds['audit:read']
    ];
    for (const permId of moderatorPermissions) {
      await client.query(
        `INSERT INTO role_permissions (role_id, permission_id) 
         VALUES ($1, $2) 
         ON CONFLICT DO NOTHING`,
        [roleIds.moderator, permId]
      );
    }
    console.log(`✓ Assigned ${moderatorPermissions.length} permissions to moderator role`);
    
    // Create default admin user
    console.log('\nCreating default admin user...');
    const adminPassword = await bcrypt.hash('Admin123!', parseInt(process.env.BCRYPT_ROUNDS) || 12);
    const userResult = await client.query(
      `INSERT INTO users (email, password_hash, first_name, last_name, email_verified) 
       VALUES ($1, $2, $3, $4, $5) 
       ON CONFLICT (email) DO NOTHING
       RETURNING id`,
      ['admin@example.com', adminPassword, 'Admin', 'User', true]
    );
    
    if (userResult.rows.length > 0) {
      const adminUserId = userResult.rows[0].id;
      
      // Assign admin role to admin user
      await client.query(
        `INSERT INTO user_roles (user_id, role_id) 
         VALUES ($1, $2) 
         ON CONFLICT DO NOTHING`,
        [adminUserId, roleIds.admin]
      );
      console.log('✓ Admin user created: admin@example.com / Admin123!');
    } else {
      console.log('✓ Admin user already exists');
    }
    
    console.log('\n✓ Database seeded successfully!');
    console.log('\nDefault credentials:');
    console.log('  Email: admin@example.com');
    console.log('  Password: Admin123!');
    console.log('\n⚠️  IMPORTANT: Change the admin password immediately in production!\n');
    
  } catch (error) {
    console.error('Error seeding database:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

seedDatabase()
  .then(() => {
    console.log('Seed process complete!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Seed failed:', error);
    process.exit(1);
  });
