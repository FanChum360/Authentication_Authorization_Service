const express = require('express');
const router = express.Router();
const OAuth2Controller = require('../controllers/oauth2Controller');
const { authenticate, optionalAuthenticate } = require('../middleware/auth');
const { validate, authorizeSchema, tokenSchema } = require('../validators/authValidator');

/**
 * @route   GET /oauth/authorize
 * @desc    OAuth2 authorization endpoint (Authorization Code Flow)
 * @access  Private (requires user authentication)
 */
router.get(
  '/authorize',
  authenticate,
  OAuth2Controller.authorize
);

/**
 * @route   POST /oauth/token
 * @desc    OAuth2 token endpoint (exchange code for tokens)
 * @access  Public
 */
router.post(
  '/token',
  validate(tokenSchema),
  OAuth2Controller.token
);

/**
 * @route   POST /oauth/revoke
 * @desc    Revoke access or refresh token
 * @access  Public
 */
router.post(
  '/revoke',
  OAuth2Controller.revoke
);

/**
 * @route   POST /oauth/introspect
 * @desc    Token introspection endpoint
 * @access  Public (requires client authentication)
 */
router.post(
  '/introspect',
  OAuth2Controller.introspect
);

/**
 * @route   GET /oauth/userinfo
 * @desc    Get user info (OpenID Connect)
 * @access  Private
 */
router.get(
  '/userinfo',
  authenticate,
  OAuth2Controller.userinfo
);

/**
 * @route   GET /.well-known/oauth-authorization-server
 * @desc    OAuth2 server metadata (discovery)
 * @access  Public
 */
router.get(
  '/.well-known/oauth-authorization-server',
  OAuth2Controller.discovery
);

module.exports = router;
