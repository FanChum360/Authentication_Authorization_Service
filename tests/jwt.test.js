const JWTService = require('../src/utils/jwt');

// Mock environment variables
process.env.JWT_SECRET = 'test-jwt-secret-key';
process.env.REFRESH_TOKEN_SECRET = 'test-refresh-secret-key';
process.env.JWT_ISSUER = 'test-auth-service';

describe('JWTService', () => {
  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    roles: ['user'],
    permissions: ['profile:read', 'profile:write'],
  };

  describe('generateAccessToken', () => {
    it('should generate a valid access token', () => {
      const token = JWTService.generateAccessToken(mockUser);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.').length).toBe(3); // JWT has 3 parts
    });

    it('should include user data in token', () => {
      const token = JWTService.generateAccessToken(mockUser);
      const decoded = JWTService.decode(token);

      expect(decoded.payload.sub).toBe(mockUser.id);
      expect(decoded.payload.email).toBe(mockUser.email);
      expect(decoded.payload.roles).toEqual(mockUser.roles);
      expect(decoded.payload.permissions).toEqual(mockUser.permissions);
    });

    it('should set token type to access', () => {
      const token = JWTService.generateAccessToken(mockUser);
      const decoded = JWTService.decode(token);

      expect(decoded.payload.type).toBe('access');
    });

    it('should include jti (JWT ID)', () => {
      const token = JWTService.generateAccessToken(mockUser);
      const decoded = JWTService.decode(token);

      expect(decoded.payload.jti).toBeDefined();
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate a valid refresh token', () => {
      const token = JWTService.generateRefreshToken(mockUser.id);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.').length).toBe(3);
    });

    it('should include user ID in token', () => {
      const token = JWTService.generateRefreshToken(mockUser.id);
      const decoded = JWTService.decode(token);

      expect(decoded.payload.sub).toBe(mockUser.id);
    });

    it('should set token type to refresh', () => {
      const token = JWTService.generateRefreshToken(mockUser.id);
      const decoded = JWTService.decode(token);

      expect(decoded.payload.type).toBe('refresh');
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify a valid access token', () => {
      const token = JWTService.generateAccessToken(mockUser);
      const decoded = JWTService.verifyAccessToken(token);

      expect(decoded.sub).toBe(mockUser.id);
      expect(decoded.email).toBe(mockUser.email);
    });

    it('should throw error for invalid token', () => {
      expect(() => {
        JWTService.verifyAccessToken('invalid-token');
      }).toThrow();
    });

    it('should throw error for refresh token when expecting access token', () => {
      const refreshToken = JWTService.generateRefreshToken(mockUser.id);

      expect(() => {
        JWTService.verifyAccessToken(refreshToken);
      }).toThrow();
    });
  });

  describe('verifyRefreshToken', () => {
    it('should verify a valid refresh token', () => {
      const token = JWTService.generateRefreshToken(mockUser.id);
      const decoded = JWTService.verifyRefreshToken(token);

      expect(decoded.sub).toBe(mockUser.id);
      expect(decoded.type).toBe('refresh');
    });

    it('should throw error for invalid token', () => {
      expect(() => {
        JWTService.verifyRefreshToken('invalid-token');
      }).toThrow();
    });
  });

  describe('decode', () => {
    it('should decode token without verification', () => {
      const token = JWTService.generateAccessToken(mockUser);
      const decoded = JWTService.decode(token);

      expect(decoded.header).toBeDefined();
      expect(decoded.payload).toBeDefined();
      expect(decoded.signature).toBeDefined();
    });

    it('should return null for invalid token', () => {
      const decoded = JWTService.decode('invalid-token');

      expect(decoded).toBeNull();
    });
  });

  describe('getTokenExpiration', () => {
    it('should return expiration date for valid token', () => {
      const token = JWTService.generateAccessToken(mockUser);
      const expiration = JWTService.getTokenExpiration(token);

      expect(expiration).toBeInstanceOf(Date);
      expect(expiration.getTime()).toBeGreaterThan(Date.now());
    });

    it('should return null for invalid token', () => {
      const expiration = JWTService.getTokenExpiration('invalid-token');

      expect(expiration).toBeNull();
    });
  });
});
