const Joi = require('joi');

/**
 * Registration validation schema
 */
const registerSchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.email': 'Please provide a valid email address',
    'any.required': 'Email is required',
  }),
  password: Joi.string().min(8).required().messages({
    'string.min': 'Password must be at least 8 characters long',
    'any.required': 'Password is required',
  }),
  firstName: Joi.string().min(1).max(100).required().messages({
    'string.min': 'First name cannot be empty',
    'string.max': 'First name is too long',
    'any.required': 'First name is required',
  }),
  lastName: Joi.string().min(1).max(100).required().messages({
    'string.min': 'Last name cannot be empty',
    'string.max': 'Last name is too long',
    'any.required': 'Last name is required',
  }),
});

/**
 * Login validation schema
 */
const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.email': 'Please provide a valid email address',
    'any.required': 'Email is required',
  }),
  password: Joi.string().required().messages({
    'any.required': 'Password is required',
  }),
});

/**
 * Refresh token validation schema
 */
const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string().required().messages({
    'any.required': 'Refresh token is required',
  }),
});

/**
 * OAuth2 authorization request validation
 */
const authorizeSchema = Joi.object({
  response_type: Joi.string().valid('code').required(),
  client_id: Joi.string().required(),
  redirect_uri: Joi.string().uri().required(),
  scope: Joi.string().optional(),
  state: Joi.string().optional(),
  code_challenge: Joi.string().optional(),
  code_challenge_method: Joi.string().valid('S256', 'plain').optional(),
});

/**
 * OAuth2 token request validation
 */
const tokenSchema = Joi.object({
  grant_type: Joi.string()
    .valid('authorization_code', 'refresh_token', 'client_credentials')
    .required(),
  code: Joi.string().when('grant_type', {
    is: 'authorization_code',
    then: Joi.required(),
  }),
  redirect_uri: Joi.string().when('grant_type', {
    is: 'authorization_code',
    then: Joi.required(),
  }),
  client_id: Joi.string().required(),
  client_secret: Joi.string().required(),
  code_verifier: Joi.string().optional(),
  refresh_token: Joi.string().when('grant_type', {
    is: 'refresh_token',
    then: Joi.required(),
  }),
  scope: Joi.string().optional(),
});

/**
 * Validation middleware factory
 */
const validate = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errors = error.details.map((detail) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      return res.status(400).json({
        error: 'Validation Error',
        details: errors,
      });
    }

    // Replace req.body with validated and sanitized data
    req.body = value;
    next();
  };
};

module.exports = {
  validate,
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  authorizeSchema,
  tokenSchema,
};
