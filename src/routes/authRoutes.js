const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const { validate, registerSchema, loginSchema, refreshTokenSchema } = require('../validators/authValidator');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimiter');

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post(
  '/register',
  registerLimiter,
  validate(registerSchema),
  AuthController.register
);

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post(
  '/login',
  loginLimiter,
  validate(loginSchema),
  AuthController.login
);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token
 * @access  Public
 */
router.post(
  '/refresh',
  validate(refreshTokenSchema),
  AuthController.refreshToken
);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (revoke refresh token)
 * @access  Private
 */
router.post(
  '/logout',
  authenticate,
  AuthController.logout
);

/**
 * @route   GET /api/auth/me
 * @desc    Get current user info
 * @access  Private
 */
router.get(
  '/me',
  authenticate,
  AuthController.getCurrentUser
);

/**
 * @route   GET /api/auth/health
 * @desc    Health check
 * @access  Public
 */
router.get('/health', AuthController.health);

/**
 * @route   GET /api/auth/verify-email/:token
 * @desc    Verify email address
 * @access  Public
 */
router.get(
  '/verify-email/:token',
  AuthController.verifyEmail
);

/**
 * @route   POST /api/auth/resend-verification
 * @desc    Resend verification email
 * @access  Public
 */
router.post(
  '/resend-verification',
  AuthController.resendVerification
);

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post(
  '/forgot-password',
  AuthController.forgotPassword
);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post(
  '/reset-password',
  AuthController.resetPassword
);

module.exports = router;
