const pool = require('../config/database');
const PasswordService = require('../utils/password');
const JWTService = require('../utils/jwt');
const emailService = require('./emailService');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class AuthService {
  /**
   * Register a new user
   */
  static async register({ email, password, firstName, lastName }) {
    const client = await pool.connect();

    try {
      // Check if user already exists
      const existingUser = await client.query(
        'SELECT id FROM users WHERE email = $1',
        [email.toLowerCase()]
      );

      if (existingUser.rows.length > 0) {
        throw new Error('User with this email already exists');
      }

      // Validate password strength
      const passwordValidation = PasswordService.validate(password);
      if (!passwordValidation.isValid) {
        throw new Error(passwordValidation.errors.join(', '));
      }

      // Hash password
      const passwordHash = await PasswordService.hash(password);

      // Insert user (email_verified = false by default)
      const userResult = await client.query(
        `INSERT INTO users (email, password_hash, first_name, last_name, email_verified) 
         VALUES ($1, $2, $3, $4, false) 
         RETURNING id, email, first_name, last_name, created_at`,
        [email.toLowerCase(), passwordHash, firstName, lastName]
      );

      const user = userResult.rows[0];

      // Assign default 'user' role
      const roleResult = await client.query(
        'SELECT id FROM roles WHERE name = $1',
        ['user']
      );

      if (roleResult.rows.length > 0) {
        await client.query(
          'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)',
          [user.id, roleResult.rows[0].id]
        );
      }

      // Generate email verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24); // 24 hours

      await client.query(
        `INSERT INTO email_verification_tokens (user_id, token, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, verificationToken, expiresAt]
      );

      // Send verification email (async, don't wait)
      emailService.sendVerificationEmail(
        user.email,
        verificationToken,
        user.first_name
      ).catch(err => console.error('Failed to send verification email:', err));

      return {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        createdAt: user.created_at,
        emailVerified: false,
      };
    } finally {
      client.release();
    }
  }

  /**
   * Login user
   */
  static async login({ email, password, ipAddress, userAgent }) {
    const client = await pool.connect();

    try {
      // Get user with roles and permissions
      const userResult = await client.query(
        `SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name, 
                u.is_active, u.email_verified,
                COALESCE(
                  json_agg(
                    DISTINCT jsonb_build_object('name', r.name, 'id', r.id)
                  ) FILTER (WHERE r.id IS NOT NULL), 
                  '[]'
                ) as roles,
                COALESCE(
                  json_agg(
                    DISTINCT jsonb_build_object(
                      'name', p.name, 
                      'resource', p.resource, 
                      'action', p.action
                    )
                  ) FILTER (WHERE p.id IS NOT NULL),
                  '[]'
                ) as permissions
         FROM users u
         LEFT JOIN user_roles ur ON u.id = ur.user_id
         LEFT JOIN roles r ON ur.role_id = r.id
         LEFT JOIN role_permissions rp ON r.id = rp.role_id
         LEFT JOIN permissions p ON rp.permission_id = p.id
         WHERE u.email = $1
         GROUP BY u.id`,
        [email.toLowerCase()]
      );

      if (userResult.rows.length === 0) {
        // Log failed login attempt
        await this.logAuditEvent(client, {
          action: 'login_failed',
          resource: 'auth',
          ipAddress,
          userAgent,
          status: 'failed',
          details: { reason: 'user_not_found', email },
        });
        throw new Error('Invalid email or password');
      }

      const user = userResult.rows[0];

      // Check if user is active
      if (!user.is_active) {
        throw new Error('Account is deactivated');
      }

      // Verify password
      const isValidPassword = await PasswordService.compare(
        password,
        user.password_hash
      );

      if (!isValidPassword) {
        // Log failed login attempt
        await this.logAuditEvent(client, {
          userId: user.id,
          action: 'login_failed',
          resource: 'auth',
          ipAddress,
          userAgent,
          status: 'failed',
          details: { reason: 'invalid_password' },
        });
        throw new Error('Invalid email or password');
      }

      // Generate tokens
      const accessToken = JWTService.generateAccessToken({
        id: user.id,
        email: user.email,
        roles: user.roles.map((r) => r.name),
        permissions: user.permissions.map((p) => p.name),
      });

      const refreshToken = JWTService.generateRefreshToken(user.id);

      // Store refresh token
      const expiresAt = new Date();
      expiresAt.setDate(
        expiresAt.getDate() + 7
      ); // 7 days from now

      await client.query(
        `INSERT INTO refresh_tokens (user_id, token, expires_at) 
         VALUES ($1, $2, $3)`,
        [user.id, refreshToken, expiresAt]
      );

      // Log successful login
      await this.logAuditEvent(client, {
        userId: user.id,
        action: 'login_success',
        resource: 'auth',
        ipAddress,
        userAgent,
        status: 'success',
      });

      return {
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          roles: user.roles.map((r) => r.name),
          permissions: user.permissions,
        },
      };
    } finally {
      client.release();
    }
  }

  /**
   * Refresh access token
   */
  static async refreshToken(refreshToken) {
    const client = await pool.connect();

    try {
      // Verify refresh token
      const decoded = JWTService.verifyRefreshToken(refreshToken);

      // Check if token exists and is not revoked
      const tokenResult = await client.query(
        `SELECT rt.id, rt.user_id, rt.expires_at, rt.revoked
         FROM refresh_tokens rt
         WHERE rt.token = $1`,
        [refreshToken]
      );

      if (tokenResult.rows.length === 0) {
        throw new Error('Invalid refresh token');
      }

      const token = tokenResult.rows[0];

      if (token.revoked) {
        throw new Error('Refresh token has been revoked');
      }

      if (new Date(token.expires_at) < new Date()) {
        throw new Error('Refresh token has expired');
      }

      // Get user with roles and permissions
      const userResult = await client.query(
        `SELECT u.id, u.email, u.first_name, u.last_name, u.is_active,
                COALESCE(
                  json_agg(
                    DISTINCT jsonb_build_object('name', r.name)
                  ) FILTER (WHERE r.id IS NOT NULL),
                  '[]'
                ) as roles,
                COALESCE(
                  json_agg(
                    DISTINCT jsonb_build_object('name', p.name)
                  ) FILTER (WHERE p.id IS NOT NULL),
                  '[]'
                ) as permissions
         FROM users u
         LEFT JOIN user_roles ur ON u.id = ur.user_id
         LEFT JOIN roles r ON ur.role_id = r.id
         LEFT JOIN role_permissions rp ON r.id = rp.role_id
         LEFT JOIN permissions p ON rp.permission_id = p.id
         WHERE u.id = $1
         GROUP BY u.id`,
        [token.user_id]
      );

      if (userResult.rows.length === 0 || !userResult.rows[0].is_active) {
        throw new Error('User not found or inactive');
      }

      const user = userResult.rows[0];

      // Generate new access token
      const accessToken = JWTService.generateAccessToken({
        id: user.id,
        email: user.email,
        roles: user.roles.map((r) => r.name),
        permissions: user.permissions.map((p) => p.name),
      });

      // Optional: Rotate refresh token
      const newRefreshToken = JWTService.generateRefreshToken(user.id);
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      // Revoke old refresh token
      await client.query(
        'UPDATE refresh_tokens SET revoked = true WHERE id = $1',
        [token.id]
      );

      // Store new refresh token
      await client.query(
        `INSERT INTO refresh_tokens (user_id, token, expires_at) 
         VALUES ($1, $2, $3)`,
        [user.id, newRefreshToken, expiresAt]
      );

      return {
        accessToken,
        refreshToken: newRefreshToken,
      };
    } finally {
      client.release();
    }
  }

  /**
   * Logout user (revoke refresh token)
   */
  static async logout(refreshToken) {
    const client = await pool.connect();

    try {
      await client.query(
        'UPDATE refresh_tokens SET revoked = true WHERE token = $1',
        [refreshToken]
      );

      return { success: true };
    } finally {
      client.release();
    }
  }

  /**
   * Get current user info
   */
  static async getCurrentUser(userId) {
    const client = await pool.connect();

    try {
      const result = await client.query(
        `SELECT u.id, u.email, u.first_name, u.last_name, 
                u.email_verified, u.created_at,
                COALESCE(
                  json_agg(
                    DISTINCT jsonb_build_object('name', r.name, 'description', r.description)
                  ) FILTER (WHERE r.id IS NOT NULL),
                  '[]'
                ) as roles,
                COALESCE(
                  json_agg(
                    DISTINCT jsonb_build_object(
                      'name', p.name,
                      'resource', p.resource,
                      'action', p.action
                    )
                  ) FILTER (WHERE p.id IS NOT NULL),
                  '[]'
                ) as permissions
         FROM users u
         LEFT JOIN user_roles ur ON u.id = ur.user_id
         LEFT JOIN roles r ON ur.role_id = r.id
         LEFT JOIN role_permissions rp ON r.id = rp.role_id
         LEFT JOIN permissions p ON rp.permission_id = p.id
         WHERE u.id = $1
         GROUP BY u.id`,
        [userId]
      );

      if (result.rows.length === 0) {
        throw new Error('User not found');
      }

      const user = result.rows[0];

      return {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        emailVerified: user.email_verified,
        createdAt: user.created_at,
        roles: user.roles,
        permissions: user.permissions,
      };
    } finally {
      client.release();
    }
  }

  /**
   * Log audit event
   */
  static async logAuditEvent(client, { userId, action, resource, resourceId, ipAddress, userAgent, status, details }) {
    await client.query(
      `INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address, user_agent, status, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [userId || null, action, resource, resourceId || null, ipAddress || null, userAgent || null, status || 'success', details ? JSON.stringify(details) : null]
    );
  }

  /**
   * Verify email with token
   */
  static async verifyEmail(token) {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      // Get verification token
      const tokenResult = await client.query(
        `SELECT evt.id, evt.user_id, evt.expires_at, evt.used, u.email, u.first_name
         FROM email_verification_tokens evt
         JOIN users u ON evt.user_id = u.id
         WHERE evt.token = $1`,
        [token]
      );

      if (tokenResult.rows.length === 0) {
        throw new Error('Invalid verification token');
      }

      const verificationToken = tokenResult.rows[0];

      // Check if already used
      if (verificationToken.used) {
        throw new Error('Verification token already used');
      }

      // Check if expired
      if (new Date(verificationToken.expires_at) < new Date()) {
        throw new Error('Verification token has expired');
      }

      // Mark token as used
      await client.query(
        'UPDATE email_verification_tokens SET used = true WHERE id = $1',
        [verificationToken.id]
      );

      // Update user email_verified status
      await client.query(
        'UPDATE users SET email_verified = true WHERE id = $1',
        [verificationToken.user_id]
      );

      await client.query('COMMIT');

      // Send welcome email (async, don't wait)
      emailService.sendWelcomeEmail(
        verificationToken.email,
        verificationToken.first_name
      ).catch(err => console.error('Failed to send welcome email:', err));

      return {
        success: true,
        message: 'Email verified successfully',
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Resend verification email
   */
  static async resendVerificationEmail(email) {
    const client = await pool.connect();

    try {
      // Get user
      const userResult = await client.query(
        'SELECT id, email, first_name, email_verified FROM users WHERE email = $1',
        [email.toLowerCase()]
      );

      if (userResult.rows.length === 0) {
        throw new Error('User not found');
      }

      const user = userResult.rows[0];

      // Check if already verified
      if (user.email_verified) {
        throw new Error('Email already verified');
      }

      // Invalidate old tokens
      await client.query(
        'UPDATE email_verification_tokens SET used = true WHERE user_id = $1 AND used = false',
        [user.id]
      );

      // Generate new verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24); // 24 hours

      await client.query(
        `INSERT INTO email_verification_tokens (user_id, token, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, verificationToken, expiresAt]
      );

      // Send verification email
      await emailService.sendVerificationEmail(
        user.email,
        verificationToken,
        user.first_name
      );

      return {
        success: true,
        message: 'Verification email sent',
      };
    } finally {
      client.release();
    }
  }

  /**
   * Request password reset
   */
  static async requestPasswordReset(email) {
    const client = await pool.connect();

    try {
      // Get user
      const userResult = await client.query(
        'SELECT id, email, first_name FROM users WHERE email = $1',
        [email.toLowerCase()]
      );

      // Always return success to prevent email enumeration
      if (userResult.rows.length === 0) {
        return {
          success: true,
          message: 'If the email exists, a password reset link has been sent',
        };
      }

      const user = userResult.rows[0];

      // Invalidate old tokens
      await client.query(
        'UPDATE password_reset_tokens SET used = true WHERE user_id = $1 AND used = false',
        [user.id]
      );

      // Generate password reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour

      await client.query(
        `INSERT INTO password_reset_tokens (user_id, token, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, resetToken, expiresAt]
      );

      // Send password reset email
      await emailService.sendPasswordResetEmail(
        user.email,
        resetToken,
        user.first_name
      );

      return {
        success: true,
        message: 'If the email exists, a password reset link has been sent',
      };
    } finally {
      client.release();
    }
  }

  /**
   * Reset password with token
   */
  static async resetPassword(token, newPassword) {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      // Validate new password
      const passwordValidation = PasswordService.validate(newPassword);
      if (!passwordValidation.isValid) {
        throw new Error(passwordValidation.errors.join(', '));
      }

      // Get reset token
      const tokenResult = await client.query(
        `SELECT id, user_id, expires_at, used
         FROM password_reset_tokens
         WHERE token = $1`,
        [token]
      );

      if (tokenResult.rows.length === 0) {
        throw new Error('Invalid reset token');
      }

      const resetToken = tokenResult.rows[0];

      // Check if already used
      if (resetToken.used) {
        throw new Error('Reset token already used');
      }

      // Check if expired
      if (new Date(resetToken.expires_at) < new Date()) {
        throw new Error('Reset token has expired');
      }

      // Hash new password
      const passwordHash = await PasswordService.hash(newPassword);

      // Update password
      await client.query(
        'UPDATE users SET password_hash = $1 WHERE id = $2',
        [passwordHash, resetToken.user_id]
      );

      // Mark token as used
      await client.query(
        'UPDATE password_reset_tokens SET used = true WHERE id = $1',
        [resetToken.id]
      );

      // Revoke all refresh tokens for security
      await client.query(
        'UPDATE refresh_tokens SET revoked = true WHERE user_id = $1',
        [resetToken.user_id]
      );

      await client.query('COMMIT');

      return {
        success: true,
        message: 'Password reset successfully',
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}

module.exports = AuthService;
