const AuthService = require('../services/authService');

class AuthController {
  /**
   * Register a new user
   * POST /api/auth/register
   */
  static async register(req, res) {
    try {
      const { email, password, firstName, lastName } = req.body;

      const user = await AuthService.register({
        email,
        password,
        firstName,
        lastName,
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: user,
      });
    } catch (error) {
      res.status(400).json({
        error: 'Registration Failed',
        message: error.message,
      });
    }
  }

  /**
   * Login user
   * POST /api/auth/login
   */
  static async login(req, res) {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.headers['user-agent'];

      const result = await AuthService.login({
        email,
        password,
        ipAddress,
        userAgent,
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: result,
      });
    } catch (error) {
      res.status(401).json({
        error: 'Login Failed',
        message: error.message,
      });
    }
  }

  /**
   * Refresh access token
   * POST /api/auth/refresh
   */
  static async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      const result = await AuthService.refreshToken(refreshToken);

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: result,
      });
    } catch (error) {
      res.status(401).json({
        error: 'Token Refresh Failed',
        message: error.message,
      });
    }
  }

  /**
   * Logout user
   * POST /api/auth/logout
   */
  static async logout(req, res) {
    try {
      const { refreshToken } = req.body;

      await AuthService.logout(refreshToken);

      res.json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      res.status(400).json({
        error: 'Logout Failed',
        message: error.message,
      });
    }
  }

  /**
   * Get current user info
   * GET /api/auth/me
   */
  static async getCurrentUser(req, res) {
    try {
      const user = await AuthService.getCurrentUser(req.user.id);

      res.json({
        success: true,
        data: user,
      });
    } catch (error) {
      res.status(400).json({
        error: 'Failed to Get User',
        message: error.message,
      });
    }
  }

  /**
   * Health check
   * GET /api/auth/health
   */
  static async health(req, res) {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'auth-service',
    });
  }

  /**
   * Verify email with token
   * GET /api/auth/verify-email/:token
   */
  static async verifyEmail(req, res) {
    try {
      const { token } = req.params;

      const result = await AuthService.verifyEmail(token);

      res.json({
        success: true,
        message: result.message,
      });
    } catch (error) {
      res.status(400).json({
        error: 'Email Verification Failed',
        message: error.message,
      });
    }
  }

  /**
   * Resend verification email
   * POST /api/auth/resend-verification
   */
  static async resendVerification(req, res) {
    try {
      const { email } = req.body;

      const result = await AuthService.resendVerificationEmail(email);

      res.json({
        success: true,
        message: result.message,
      });
    } catch (error) {
      res.status(400).json({
        error: 'Failed to Resend Verification',
        message: error.message,
      });
    }
  }

  /**
   * Request password reset
   * POST /api/auth/forgot-password
   */
  static async forgotPassword(req, res) {
    try {
      const { email } = req.body;

      const result = await AuthService.requestPasswordReset(email);

      // Always return success to prevent email enumeration
      res.json({
        success: true,
        message: result.message,
      });
    } catch (error) {
      // Even on error, return success for security
      res.json({
        success: true,
        message: 'If the email exists, a password reset link has been sent',
      });
    }
  }

  /**
   * Reset password with token
   * POST /api/auth/reset-password
   */
  static async resetPassword(req, res) {
    try {
      const { token, password } = req.body;

      const result = await AuthService.resetPassword(token, password);

      res.json({
        success: true,
        message: result.message,
      });
    } catch (error) {
      res.status(400).json({
        error: 'Password Reset Failed',
        message: error.message,
      });
    }
  }
}

module.exports = AuthController;
