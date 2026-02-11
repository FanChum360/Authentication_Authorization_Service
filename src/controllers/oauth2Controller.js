const OAuth2Service = require('../services/oauth2Service');

class OAuth2Controller {
  /**
   * OAuth2 Authorization Endpoint
   * GET /oauth/authorize
   * 
   * Initiates the authorization code flow
   */
  static async authorize(req, res) {
    try {
      const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method,
      } = req.query;

      // Validate that user is authenticated
      if (!req.user) {
        // Redirect to login with return URL
        const loginUrl = `/login?redirect=${encodeURIComponent(req.originalUrl)}`;
        return res.redirect(loginUrl);
      }

      // For demo purposes, auto-approve
      // In production, show consent screen
      const result = await OAuth2Service.generateAuthorizationCode({
        userId: req.user.id,
        clientId: client_id,
        redirectUri: redirect_uri,
        scope: scope || '',
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method || 'S256',
      });

      // Redirect back to client with authorization code
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.append('code', result.code);
      if (state) {
        redirectUrl.searchParams.append('state', state);
      }

      res.redirect(redirectUrl.toString());
    } catch (error) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: error.message,
      });
    }
  }

  /**
   * OAuth2 Token Endpoint
   * POST /oauth/token
   * 
   * Exchanges authorization code for tokens
   * Or handles client credentials flow
   */
  static async token(req, res) {
    try {
      const { grant_type } = req.body;

      let result;

      switch (grant_type) {
        case 'authorization_code':
          result = await OAuth2Service.exchangeCodeForTokens({
            code: req.body.code,
            clientId: req.body.client_id,
            clientSecret: req.body.client_secret,
            redirectUri: req.body.redirect_uri,
            codeVerifier: req.body.code_verifier,
          });
          break;

        case 'client_credentials':
          result = await OAuth2Service.clientCredentials({
            clientId: req.body.client_id,
            clientSecret: req.body.client_secret,
            scope: req.body.scope,
          });
          break;

        case 'refresh_token':
          result = await require('../services/authService').refreshToken(
            req.body.refresh_token
          );
          break;

        default:
          throw new Error('Unsupported grant type');
      }

      res.json({
        access_token: result.accessToken,
        token_type: result.tokenType || 'Bearer',
        expires_in: result.expiresIn,
        refresh_token: result.refreshToken,
        scope: result.scope,
      });
    } catch (error) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: error.message,
      });
    }
  }

  /**
   * OAuth2 Token Revocation Endpoint
   * POST /oauth/revoke
   */
  static async revoke(req, res) {
    try {
      const { token, token_type_hint } = req.body;

      await OAuth2Service.revokeToken({
        token,
        tokenTypeHint: token_type_hint,
      });

      res.status(200).json({
        success: true,
      });
    } catch (error) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: error.message,
      });
    }
  }

  /**
   * OAuth2 Token Introspection Endpoint
   * POST /oauth/introspect
   */
  static async introspect(req, res) {
    try {
      const { token } = req.body;

      if (!token) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Token is required',
        });
      }

      const result = await OAuth2Service.introspectToken(token);

      res.json(result);
    } catch (error) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: error.message,
      });
    }
  }

  /**
   * OAuth2 UserInfo Endpoint (OpenID Connect)
   * GET /oauth/userinfo
   */
  static async userinfo(req, res) {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'invalid_token',
          error_description: 'The access token is invalid or expired',
        });
      }

      const user = await require('../services/authService').getCurrentUser(
        req.user.id
      );

      // Return OpenID Connect standard claims
      res.json({
        sub: user.id,
        email: user.email,
        email_verified: user.emailVerified,
        given_name: user.firstName,
        family_name: user.lastName,
        name: `${user.firstName} ${user.lastName}`,
      });
    } catch (error) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: error.message,
      });
    }
  }

  /**
   * OAuth2 Discovery Endpoint (OpenID Connect)
   * GET /.well-known/oauth-authorization-server
   */
  static async discovery(req, res) {
    const baseUrl = `${req.protocol}://${req.get('host')}`;

    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      revocation_endpoint: `${baseUrl}/oauth/revoke`,
      introspection_endpoint: `${baseUrl}/oauth/introspect`,
      userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      response_types_supported: ['code', 'token'],
      grant_types_supported: [
        'authorization_code',
        'client_credentials',
        'refresh_token',
      ],
      token_endpoint_auth_methods_supported: ['client_secret_post'],
      code_challenge_methods_supported: ['S256', 'plain'],
      scopes_supported: ['openid', 'profile', 'email'],
    });
  }
}

module.exports = OAuth2Controller;
