# Authentication & Authorization Service

Built and studied a full OAuth2 + JWT authentication system to deeply understand modern authentication architecture.

## Features

- **JWT Authentication**: Secure token-based authentication
- **OAuth2 Implementation**: Industry-standard authorization framework
- **Token Refresh**: Automatic token renewal without re-authentication
- **RBAC**: Fine-grained role and permission management
- **Email Verification**: Email confirmation on registration
- **Password Reset**: Secure password recovery via email
- **Password Security**: Bcrypt hashing with salt
- **Rate Limiting**: Brute-force protection
- **Session Management**: Active session tracking and revocation
- **Audit Logging**: Security event tracking

## Tech Stack

- **Backend**: Node.js with Express
- **Database**: PostgreSQL
- **Authentication**: JWT, bcrypt
- **Validation**: Joi
- **Security**: helmet, cors, rate-limiting

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ├─ POST /auth/register
       ├─ POST /auth/login
       ├─ POST /auth/refresh
       ├─ POST /auth/logout
       ├─ GET  /auth/me
       │
┌──────▼──────────┐
│  Auth Service   │
│  (Express API)  │
└──────┬──────────┘
       │
┌──────▼──────────┐
│   PostgreSQL    │
│   - users       │
│   - roles       │
│   - permissions │
│   - sessions    │
└─────────────────┘
```

## Database Schema

### Users Table
- id, email, password_hash, first_name, last_name
- email_verified, created_at, updated_at

### Roles Table
- id, name, description

### Permissions Table
- id, name, description, resource, action

### User_Roles Table (Many-to-Many)
- user_id, role_id

### Role_Permissions Table (Many-to-Many)
- role_id, permission_id

### Refresh_Tokens Table
- id, user_id, token, expires_at, created_at

### Audit_Logs Table
- id, user_id, action, resource, ip_address, timestamp

## Getting Started

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- npm or yarn

### Installation

```bash
# Clone and install dependencies
cd auth-service
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Initialize database
npm run db:setup

# Run migrations
npm run db:migrate

# Seed initial data
npm run db:seed

# Start development server
npm run dev
```

### Environment Variables

```env
NODE_ENV=development
PORT=3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_service
DB_USER=postgres
DB_PASSWORD=your_password

# JWT
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=15m
REFRESH_TOKEN_SECRET=your-refresh-token-secret
REFRESH_TOKEN_EXPIRES_IN=7d

# Security
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

## API Endpoints

### Authentication

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Verify Email
```http
GET /api/auth/verify-email/:token
```

#### Resend Verification Email
```http
POST /api/auth/resend-verification
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

Response:
{
  "accessToken": "eyJhbGc...",
  "refreshToken": "eyJhbGc...",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "roles": ["user"]
  }
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGc..."
}
```

#### Logout
```http
POST /api/auth/logout
Authorization: Bearer {accessToken}

{
  "refreshToken": "eyJhbGc..."
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer {accessToken}
```

### User Management (Admin)

```http
GET    /api/users           # List users
GET    /api/users/:id       # Get user
PUT    /api/users/:id       # Update user
DELETE /api/users/:id       # Delete user
POST   /api/users/:id/roles # Assign role
```

### Role Management (Admin)

```http
GET    /api/roles                    # List roles
POST   /api/roles                    # Create role
GET    /api/roles/:id                # Get role
PUT    /api/roles/:id                # Update role
DELETE /api/roles/:id                # Delete role
POST   /api/roles/:id/permissions    # Assign permission
```

## Security Features

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### Token Security
- Access tokens: Short-lived (15 minutes)
- Refresh tokens: Long-lived (7 days)
- Tokens stored securely (refresh tokens in DB)
- Token rotation on refresh
- Blacklist support for revoked tokens

### Rate Limiting
- Login attempts: 5 per 15 minutes per IP
- Registration: 3 per hour per IP
- API calls: 100 per 15 minutes per user

### Additional Security
- CORS configuration
- Helmet.js security headers
- SQL injection prevention (parameterized queries)
- XSS protection
- CSRF protection (when needed)

## Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test suite
npm test -- auth.test.js
```

## Deployment

### Docker

```bash
# Build image
docker build -t auth-service .

# Run with docker-compose
docker-compose up -d
```

### Production Considerations

1. **Environment**: Use production-grade secrets management
2. **Database**: Enable SSL, use connection pooling
3. **Logging**: Implement centralized logging (ELK, Datadog)
4. **Monitoring**: Add health checks and metrics
5. **Scaling**: Use Redis for session storage in multi-instance setups
6. **HTTPS**: Always use TLS in production
7. **Backups**: Regular database backups

## Project Structure

```
auth-service/
├── src/
│   ├── config/         # Configuration files
│   ├── controllers/    # Route controllers
│   ├── middleware/     # Custom middleware
│   ├── models/         # Database models
│   ├── routes/         # API routes
│   ├── services/       # Business logic
│   ├── utils/          # Helper functions
│   └── validators/     # Input validation
├── database/
│   ├── migrations/     # DB migrations
│   └── seeds/          # Seed data
├── tests/              # Test files
├── .env.example        # Example environment variables
├── docker-compose.yml  # Docker composition
├── Dockerfile          # Docker image definition
└── package.json
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License
