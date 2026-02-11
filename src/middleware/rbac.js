/**
 * Middleware to check if user has required role(s)
 */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
      });
    }

    const userRoles = req.user.roles || [];
    const hasRole = roles.some((role) => userRoles.includes(role));

    if (!hasRole) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Required role(s): ${roles.join(', ')}`,
      });
    }

    next();
  };
};

/**
 * Middleware to check if user has required permission(s)
 */
const requirePermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
      });
    }

    const userPermissions = req.user.permissions || [];
    const hasPermission = permissions.every((perm) =>
      userPermissions.includes(perm)
    );

    if (!hasPermission) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Required permission(s): ${permissions.join(', ')}`,
      });
    }

    next();
  };
};

/**
 * Middleware to check if user has ANY of the required permissions
 */
const requireAnyPermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
      });
    }

    const userPermissions = req.user.permissions || [];
    const hasPermission = permissions.some((perm) =>
      userPermissions.includes(perm)
    );

    if (!hasPermission) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Required any of: ${permissions.join(', ')}`,
      });
    }

    next();
  };
};

/**
 * Middleware to check resource ownership
 * Allows users to access their own resources
 */
const requireOwnership = (userIdParam = 'id') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
      });
    }

    const resourceUserId = req.params[userIdParam] || req.body[userIdParam];

    // Allow if user is accessing their own resource OR is an admin
    if (
      req.user.id === resourceUserId ||
      req.user.roles.includes('admin')
    ) {
      return next();
    }

    return res.status(403).json({
      error: 'Forbidden',
      message: 'You can only access your own resources',
    });
  };
};

/**
 * Combine role and permission checks
 */
const requireRoleOrPermission = (roles, permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
      });
    }

    const userRoles = req.user.roles || [];
    const userPermissions = req.user.permissions || [];

    const hasRole = roles.some((role) => userRoles.includes(role));
    const hasPermission = permissions.some((perm) =>
      userPermissions.includes(perm)
    );

    if (!hasRole && !hasPermission) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Insufficient privileges',
      });
    }

    next();
  };
};

module.exports = {
  requireRole,
  requirePermission,
  requireAnyPermission,
  requireOwnership,
  requireRoleOrPermission,
};
