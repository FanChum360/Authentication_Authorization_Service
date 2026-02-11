const request = require('supertest');
const app = require('../src/server');

describe('Authentication API', () => {
  let accessToken;
  let refreshToken;
  const testUser = {
    email: `test${Date.now()}@example.com`,
    password: 'TestPass123!',
    firstName: 'Test',
    lastName: 'User',
  };

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data.email).toBe(testUser.email);
    });

    it('should reject duplicate email', async () => {
      await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(400);
    });

    it('should reject weak password', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({
          ...testUser,
          email: 'another@example.com',
          password: '123',
        })
        .expect(400);
    });

    it('should reject invalid email', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({
          ...testUser,
          email: 'invalid-email',
        })
        .expect(400);
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');
      expect(response.body.data.user.email).toBe(testUser.email);

      accessToken = response.body.data.accessToken;
      refreshToken = response.body.data.refreshToken;
    });

    it('should reject invalid password', async () => {
      await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword123!',
        })
        .expect(401);
    });

    it('should reject non-existent user', async () => {
      await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'Password123!',
        })
        .expect(401);
    });
  });

  describe('GET /api/auth/me', () => {
    it('should get current user with valid token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe(testUser.email);
      expect(response.body.data).toHaveProperty('roles');
      expect(response.body.data).toHaveProperty('permissions');
    });

    it('should reject request without token', async () => {
      await request(app).get('/api/auth/me').expect(401);
    });

    it('should reject request with invalid token', async () => {
      await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });
  });

  describe('POST /api/auth/refresh', () => {
    it('should refresh access token with valid refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .send({
          refreshToken,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('accessToken');
      expect(response.body.data).toHaveProperty('refreshToken');

      // Update tokens for next tests
      accessToken = response.body.data.accessToken;
      refreshToken = response.body.data.refreshToken;
    });

    it('should reject invalid refresh token', async () => {
      await request(app)
        .post('/api/auth/refresh')
        .send({
          refreshToken: 'invalid-refresh-token',
        })
        .expect(401);
    });
  });

  describe('POST /api/auth/logout', () => {
    it('should logout successfully', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          refreshToken,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should not allow token refresh after logout', async () => {
      await request(app)
        .post('/api/auth/refresh')
        .send({
          refreshToken,
        })
        .expect(401);
    });
  });

  describe('GET /api/auth/health', () => {
    it('should return health status', async () => {
      const response = await request(app)
        .get('/api/auth/health')
        .expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.service).toBe('auth-service');
    });
  });
});

describe('Rate Limiting', () => {
  it('should rate limit login attempts', async () => {
    const attempts = [];

    // Make 6 rapid login attempts (limit is 5)
    for (let i = 0; i < 6; i++) {
      attempts.push(
        request(app)
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'wrong',
          })
      );
    }

    const responses = await Promise.all(attempts);
    const rateLimited = responses.some((r) => r.status === 429);

    expect(rateLimited).toBe(true);
  });
});
