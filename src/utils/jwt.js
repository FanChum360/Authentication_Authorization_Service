const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

class JWTService {
  /**
   * Generate access token
   */
  static generateAccessToken(user) {
    const payload = {
      sub: user.id,
      email: user.email,
      roles: user.roles || [],
      permissions: user.permissions || [],
      type: 'access',
      jti: uuidv4(), // JWT ID for tracking
    };

    return jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '15m',
      issuer: process.env.JWT_ISSUER || 'auth-service',
      audience: 'api',
    });
  }

  /**
   * Generate refresh token
   */
  static generateRefreshToken(userId) {
    const payload = {
      sub: userId,
      type: 'refresh',
      jti: uuidv4(),
    };

    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d',
      issuer: process.env.JWT_ISSUER || 'auth-service',
    });
  }

  /**
   * Verify access token
   */
  static verifyAccessToken(token) {
    try {
      return jwt.verify(token, process.env.JWT_SECRET, {
        issuer: process.env.JWT_ISSUER || 'auth-service',
        audience: 'api',
      });
    } catch (error) {
      throw new Error(`Invalid access token: ${error.message}`);
    }
  }

  /**
   * Verify refresh token
   */
  static verifyRefreshToken(token) {
    try {
      return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, {
        issuer: process.env.JWT_ISSUER || 'auth-service',
      });
    } catch (error) {
      throw new Error(`Invalid refresh token: ${error.message}`);
    }
  }

  /**
   * Decode token without verification (for debugging)
   */
  static decode(token) {
    return jwt.decode(token, { complete: true });
  }

  /**
   * Get token expiration time
   */
  static getTokenExpiration(token) {
    const decoded = this.decode(token);
    if (decoded && decoded.payload && decoded.payload.exp) {
      return new Date(decoded.payload.exp * 1000);
    }
    return null;
  }
}

module.exports = JWTService;
