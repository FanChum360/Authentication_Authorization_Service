const rateLimit = require('express-rate-limit');

/**
 * General API rate limiter
 */
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    error: 'Too Many Requests',
    message: 'Too many requests from this IP, please try again later',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Strict limiter for login attempts
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 5,
  skipSuccessfulRequests: true, // Don't count successful logins
  message: {
    error: 'Too Many Login Attempts',
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Limiter for registration
 */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: parseInt(process.env.REGISTER_RATE_LIMIT_MAX) || 3,
  message: {
    error: 'Too Many Registration Attempts',
    message: 'Too many registration attempts from this IP, please try again after 1 hour',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Limiter for password reset requests
 */
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: {
    error: 'Too Many Password Reset Requests',
    message: 'Too many password reset requests, please try again after 1 hour',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = {
  apiLimiter,
  loginLimiter,
  registerLimiter,
  passwordResetLimiter,
};
