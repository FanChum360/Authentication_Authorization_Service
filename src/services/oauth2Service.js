const pool = require('../config/database');
const JWTService = require('../utils/jwt');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

class OAuth2Service {
  /**
   * Generate authorization code
   * Used in Authorization Code Flow
   */
  static async generateAuthorizationCode({ userId, clientId, redirectUri, scope, codeChallenge, codeChallengeMethod }) {
    const client = await pool.connect();

    try {
      // Validate client
      const clientResult = await client.query(
        'SELECT id, redirect_uris FROM oauth_clients WHERE client_id = $1 AND is_active = true',
        [clientId]
      );

      if (clientResult.rows.length === 0) {
        throw new Error('Invalid client');
      }

      const oauthClient = clientResult.rows[0];

      // Validate redirect URI
      const redirectUris = oauthClient.redirect_uris || [];
      if (!redirectUris.includes(redirectUri)) {
        throw new Error('Invalid redirect URI');
      }

      // Generate authorization code
      const code = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 10); // 10 minutes

      // Store authorization code
      await client.query(
        `INSERT INTO authorization_codes 
         (code, user_id, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [code, userId, oauthClient.id, redirectUri, scope, codeChallenge, codeChallengeMethod, expiresAt]
      );

      return {
        code,
        redirectUri,
        expiresIn: 600, // 10 minutes in seconds
      };
    } finally {
      client.release();
    }
  }

  /**
   * Exchange authorization code for tokens
   * Completes Authorization Code Flow
   */
  static async exchangeCodeForTokens({ code, clientId, clientSecret, redirectUri, codeVerifier }) {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      // Validate client credentials
      const clientResult = await client.query(
        'SELECT id, client_secret FROM oauth_clients WHERE client_id = $1 AND is_active = true',
        [clientId]
      );

      if (clientResult.rows.length === 0) {
        throw new Error('Invalid client');
      }

      const oauthClient = clientResult.rows[0];

      // Verify client secret
      if (oauthClient.client_secret !== clientSecret) {
        throw new Error('Invalid client credentials');
      }

      // Get authorization code
      const codeResult = await client.query(
        `SELECT id, user_id, redirect_uri, scope, code_challenge, 
                code_challenge_method, expires_at, used
         FROM authorization_codes
         WHERE code = $1`,
        [code]
      );

      if (codeResult.rows.length === 0) {
        throw new Error('Invalid authorization code');
      }

      const authCode = codeResult.rows[0];

      // Check if code has been used
      if (authCode.used) {
        throw new Error('Authorization code already used');
      }

      // Check if code has expired
      if (new Date(authCode.expires_at) < new Date()) {
        throw new Error('Authorization code expired');
      }

      // Validate redirect URI
      if (authCode.redirect_uri !== redirectUri) {
        throw new Error('Redirect URI mismatch');
      }

      // Verify PKCE if used
      if (authCode.code_challenge) {
        if (!codeVerifier) {
          throw new Error('Code verifier required');
        }

        const isValid = this.verifyPKCE(
          codeVerifier,
          authCode.code_challenge,
          authCode.code_challenge_method
        );

        if (!isValid) {
          throw new Error('Invalid code verifier');
        }
      }

      // Get user with roles and permissions
      const userResult = await client.query(
        `SELECT u.id, u.email,
                COALESCE(
                  json_agg(DISTINCT r.name) FILTER (WHERE r.id IS NOT NULL),
                  '[]'
                ) as roles,
                COALESCE(
                  json_agg(DISTINCT p.name) FILTER (WHERE p.id IS NOT NULL),
                  '[]'
                ) as permissions
         FROM users u
         LEFT JOIN user_roles ur ON u.id = ur.user_id
         LEFT JOIN roles r ON ur.role_id = r.id
         LEFT JOIN role_permissions rp ON r.id = rp.role_id
         LEFT JOIN permissions p ON rp.permission_id = p.id
         WHERE u.id = $1
         GROUP BY u.id`,
        [authCode.user_id]
      );

      if (userResult.rows.length === 0) {
        throw new Error('User not found');
      }

      const user = userResult.rows[0];

      // Generate tokens
      const accessToken = JWTService.generateAccessToken({
        id: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        scope: authCode.scope,
      });

      const refreshToken = JWTService.generateRefreshToken(user.id);

      // Store refresh token
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await client.query(
        `INSERT INTO refresh_tokens (user_id, token, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, refreshToken, expiresAt]
      );

      // Mark authorization code as used
      await client.query(
        'UPDATE authorization_codes SET used = true WHERE id = $1',
        [authCode.id]
      );

      await client.query('COMMIT');

      return {
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresIn: 900, // 15 minutes
        scope: authCode.scope,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Client Credentials Flow
   * For server-to-server authentication
   */
  static async clientCredentials({ clientId, clientSecret, scope }) {
    const client = await pool.connect();

    try {
      // Validate client credentials
      const clientResult = await client.query(
        'SELECT id, allowed_scopes FROM oauth_clients WHERE client_id = $1 AND client_secret = $2 AND is_active = true',
        [clientId, clientSecret]
      );

      if (clientResult.rows.length === 0) {
        throw new Error('Invalid client credentials');
      }

      const oauthClient = clientResult.rows[0];

      // Validate scope
      const requestedScopes = scope ? scope.split(' ') : [];
      const allowedScopes = oauthClient.allowed_scopes || [];

      const invalidScopes = requestedScopes.filter(s => !allowedScopes.includes(s));
      if (invalidScopes.length > 0) {
        throw new Error(`Invalid scopes: ${invalidScopes.join(', ')}`);
      }

      // Generate client token (no user context)
      const payload = {
        sub: oauthClient.id,
        client_id: clientId,
        scope: requestedScopes.join(' '),
        type: 'client',
        jti: uuidv4(),
      };

      const accessToken = require('jsonwebtoken').sign(
        payload,
        process.env.JWT_SECRET,
        {
          expiresIn: '1h',
          issuer: process.env.JWT_ISSUER || 'auth-service',
          audience: 'api',
        }
      );

      return {
        accessToken,
        tokenType: 'Bearer',
        expiresIn: 3600, // 1 hour
        scope: requestedScopes.join(' '),
      };
    } finally {
      client.release();
    }
  }

  /**
   * Verify PKCE code challenge
   */
  static verifyPKCE(codeVerifier, codeChallenge, method = 'S256') {
    let challenge;

    if (method === 'S256') {
      challenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
    } else if (method === 'plain') {
      challenge = codeVerifier;
    } else {
      throw new Error('Unsupported code challenge method');
    }

    return challenge === codeChallenge;
  }

  /**
   * Revoke token (logout)
   */
  static async revokeToken({ token, tokenTypeHint }) {
    const client = await pool.connect();

    try {
      if (tokenTypeHint === 'refresh_token' || !tokenTypeHint) {
        await client.query(
          'UPDATE refresh_tokens SET revoked = true WHERE token = $1',
          [token]
        );
      }

      // For access tokens, we'd need a token blacklist table
      // This is a simplified implementation

      return { success: true };
    } finally {
      client.release();
    }
  }

  /**
   * Introspect token (check if valid)
   */
  static async introspectToken(token) {
    try {
      const decoded = JWTService.verifyAccessToken(token);

      return {
        active: true,
        scope: decoded.scope,
        client_id: decoded.client_id,
        username: decoded.email,
        token_type: 'Bearer',
        exp: decoded.exp,
        iat: decoded.iat,
        sub: decoded.sub,
      };
    } catch (error) {
      return {
        active: false,
      };
    }
  }
}

module.exports = OAuth2Service;
