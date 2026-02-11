const JWTService = require('../utils/jwt');

/**
 * Middleware to authenticate requests using JWT
 */
const authenticate = (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'No token provided',
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify token
    const decoded = JWTService.verifyAccessToken(token);

    // Attach user info to request
    req.user = {
      id: decoded.sub,
      email: decoded.email,
      roles: decoded.roles || [],
      permissions: decoded.permissions || [],
    };

    next();
  } catch (error) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: error.message,
    });
  }
};

/**
 * Optional authentication - doesn't fail if no token
 */
const optionalAuthenticate = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded = JWTService.verifyAccessToken(token);

      req.user = {
        id: decoded.sub,
        email: decoded.email,
        roles: decoded.roles || [],
        permissions: decoded.permissions || [],
      };
    }

    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};

module.exports = {
  authenticate,
  optionalAuthenticate,
};
