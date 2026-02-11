# Architecture Documentation

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Applications                      │
│  (Web App, Mobile App, Third-Party Services, Microservices)    │
└────────────────┬───────────────────────┬────────────────────────┘
                 │                       │
                 │ HTTPS/JWT             │ OAuth2
                 │                       │
┌────────────────▼───────────────────────▼────────────────────────┐
│                     API Gateway / Load Balancer                  │
│                    (nginx, AWS ALB, etc.)                        │
└────────────────┬───────────────────────┬────────────────────────┘
                 │                       │
      ┌──────────▼──────────┐ ┌─────────▼──────────┐
      │  /api/auth/*        │ │   /oauth/*         │
      │  Authentication     │ │   OAuth2           │
      │  Endpoints          │ │   Endpoints        │
      └──────────┬──────────┘ └─────────┬──────────┘
                 │                       │
                 └───────────┬───────────┘
                             │
                 ┌───────────▼───────────┐
                 │   Express.js Server   │
                 │   - Helmet (Security) │
                 │   - CORS              │
                 │   - Rate Limiting     │
                 │   - Request Logging   │
                 └───────────┬───────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
┌─────────▼─────────┐ ┌──────▼─────────┐ ┌────▼────────┐
│ Authentication    │ │ Authorization  │ │   OAuth2    │
│ Service           │ │ (RBAC) Service │ │   Service   │
│ - Register        │ │ - Roles        │ │ - Auth Code │
│ - Login           │ │ - Permissions  │ │ - Client    │
│ - Refresh         │ │ - Access Ctrl  │ │   Creds     │
│ - Logout          │ └────────┬───────┘ │ - Introspect│
└─────────┬─────────┘          │         └─────┬───────┘
          │                    │               │
          └────────────────────┼───────────────┘
                               │
                  ┌────────────▼────────────┐
                  │  PostgreSQL Database    │
                  │  ┌──────────────────┐   │
                  │  │ users            │   │
                  │  │ roles            │   │
                  │  │ permissions      │   │
                  │  │ user_roles       │   │
                  │  │ role_permissions │   │
                  │  │ refresh_tokens   │   │
                  │  │ oauth_clients    │   │
                  │  │ authorization_   │   │
                  │  │   codes          │   │
                  │  │ audit_logs       │   │
                  │  └──────────────────┘   │
                  └─────────────────────────┘
```

## Request Flow

### 1. User Registration Flow

```
Client                Auth Service              Database
  │                        │                        │
  ├─── POST /register ────▶│                        │
  │    {email, password}   │                        │
  │                        ├─── Validate Input ────┤
  │                        │                        │
  │                        ├─── Hash Password ─────┤
  │                        │                        │
  │                        ├─── INSERT user ───────▶│
  │                        │                        │
  │                        ├─── Assign 'user' role ▶│
  │                        │                        │
  │◀─── 201 Created ───────┤                        │
  │    {user data}         │                        │
```

### 2. Login Flow (JWT)

```
Client                Auth Service              Database
  │                        │                        │
  ├──── POST /login ──────▶│                        │
  │    {email, password}   │                        │
  │                        ├── SELECT user + roles +│
  │                        │   permissions ─────────▶│
  │                        │                        │
  │                        ├── Verify password ────┤
  │                        │   (bcrypt.compare)     │
  │                        │                        │
  │                        ├── Generate JWT ───────┤
  │                        │   (access + refresh)   │
  │                        │                        │
  │                        ├── Store refresh token ▶│
  │                        │                        │
  │                        ├── Log audit event ────▶│
  │                        │                        │
  │◀─── 200 OK ────────────┤                        │
  │    {accessToken,       │                        │
  │     refreshToken}      │                        │
```

### 3. Protected Request Flow

```
Client                Auth Service              Database
  │                        │                        │
  ├─ GET /api/auth/me ────▶│                        │
  │  Authorization: Bearer │                        │
  │  {JWT token}           │                        │
  │                        ├── Verify JWT ─────────┤
  │                        │   (signature, exp)     │
  │                        │                        │
  │                        ├── Extract user info ──┤
  │                        │   from JWT payload     │
  │                        │                        │
  │                        ├── SELECT user details ▶│
  │                        │                        │
  │◀─── 200 OK ────────────┤                        │
  │    {user data}         │                        │
```

### 4. Token Refresh Flow

```
Client                Auth Service              Database
  │                        │                        │
  ├── POST /refresh ──────▶│                        │
  │   {refreshToken}       │                        │
  │                        ├── Verify refresh token┤
  │                        │                        │
  │                        ├── SELECT token from DB▶│
  │                        │   (check revoked,      │
  │                        │    expires_at)         │
  │                        │                        │
  │                        ├── Generate new tokens ┤
  │                        │                        │
  │                        ├── Revoke old token ───▶│
  │                        │                        │
  │                        ├── Store new token ────▶│
  │                        │                        │
  │◀─── 200 OK ────────────┤                        │
  │    {new tokens}        │                        │
```

### 5. OAuth2 Authorization Code Flow

```
Client App         User Browser         Auth Service         Database
  │                      │                    │                   │
  ├─ Redirect to ───────▶│                    │                   │
  │  /oauth/authorize    │                    │                   │
  │                      ├─── GET /authorize ▶│                   │
  │                      │                    ├─ Check session ──▶│
  │                      │◀── Login page ─────┤                   │
  │                      │                    │                   │
  │                      ├─── POST login ────▶│                   │
  │                      │                    ├─ Verify creds ───▶│
  │                      │                    │                   │
  │                      │                    ├─ Generate code ──▶│
  │                      │                    │                   │
  │                      │◀── Redirect + code ┤                   │
  │◀─── Callback + code ─┤                    │                   │
  │                      │                    │                   │
  ├────── POST /token ───────────────────────▶│                   │
  │       {code, client_id, client_secret}    │                   │
  │                      │                    ├─ Verify code ────▶│
  │                      │                    │                   │
  │                      │                    ├─ Generate tokens ─┤
  │                      │                    │                   │
  │◀────── {tokens} ───────────────────────────┤                   │
```

## Database Schema

### Entity Relationship Diagram

```
┌──────────────────┐         ┌──────────────────┐
│      users       │         │      roles       │
├──────────────────┤         ├──────────────────┤
│ id (PK)          │         │ id (PK)          │
│ email (UNIQUE)   │         │ name (UNIQUE)    │
│ password_hash    │         │ description      │
│ first_name       │         │ created_at       │
│ last_name        │         └──────────────────┘
│ email_verified   │                  │
│ is_active        │                  │
│ created_at       │                  │
│ updated_at       │                  │
└────────┬─────────┘                  │
         │                            │
         │      ┌─────────────────────┘
         │      │
         │      │     ┌─────────────────┐
         │      └────▶│  user_roles     │◀────┐
         │            ├─────────────────┤     │
         │            │ user_id (FK)    │     │
         │            │ role_id (FK)    │     │
         │            │ assigned_at     │     │
         │            └─────────────────┘     │
         │                                    │
         │                                    │
         │                        ┌───────────┴──────────┐
         │                        │   role_permissions   │
         │                        ├──────────────────────┤
         │                        │ role_id (FK)         │
         │                        │ permission_id (FK)   │
         │                        │ assigned_at          │
         │                        └───────────┬──────────┘
         │                                    │
         │                        ┌───────────▼──────────┐
         │                        │    permissions       │
         │                        ├──────────────────────┤
         │                        │ id (PK)              │
         │                        │ name (UNIQUE)        │
         │                        │ description          │
         │                        │ resource             │
         │                        │ action               │
         │                        │ created_at           │
         │                        └──────────────────────┘
         │
         │            ┌─────────────────┐
         └───────────▶│ refresh_tokens  │
                      ├─────────────────┤
                      │ id (PK)         │
                      │ user_id (FK)    │
                      │ token           │
                      │ expires_at      │
                      │ revoked         │
                      │ created_at      │
                      └─────────────────┘
```

## Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      Security Layers                        │
├─────────────────────────────────────────────────────────────┤
│ 1. Network Layer                                            │
│    - HTTPS/TLS encryption                                   │
│    - Firewall rules                                         │
│    - DDoS protection                                        │
├─────────────────────────────────────────────────────────────┤
│ 2. Application Layer                                        │
│    - Helmet.js (Security headers)                           │
│    - CORS configuration                                     │
│    - Input validation (Joi)                                 │
│    - SQL injection prevention                               │
├─────────────────────────────────────────────────────────────┤
│ 3. Authentication Layer                                     │
│    - Password hashing (bcrypt)                              │
│    - JWT token validation                                   │
│    - Token expiration                                       │
│    - Refresh token rotation                                 │
├─────────────────────────────────────────────────────────────┤
│ 4. Authorization Layer (RBAC)                               │
│    - Role-based access control                              │
│    - Permission checking                                    │
│    - Resource ownership validation                          │
├─────────────────────────────────────────────────────────────┤
│ 5. Rate Limiting Layer                                      │
│    - Per-IP rate limiting                                   │
│    - Endpoint-specific limits                               │
│    - Brute-force protection                                 │
├─────────────────────────────────────────────────────────────┤
│ 6. Audit Layer                                              │
│    - Comprehensive logging                                  │
│    - Security event tracking                                │
│    - Failed attempt monitoring                              │
└─────────────────────────────────────────────────────────────┘
```

## Token Lifecycle

```
┌────────────────────────────────────────────────────────────┐
│                     Token Lifecycle                        │
└────────────────────────────────────────────────────────────┘

1. Token Generation (Login)
   ├─ Access Token: 15 minutes TTL
   │  └─ Contains: user ID, email, roles, permissions
   └─ Refresh Token: 7 days TTL
      └─ Contains: user ID only

2. Token Usage
   ├─ Access Token
   │  └─ Sent in Authorization header: Bearer {token}
   └─ Refresh Token
      └─ Stored securely by client

3. Token Refresh (before access token expires)
   ├─ Client sends refresh token
   ├─ Server validates refresh token
   ├─ Server generates new access token
   ├─ Server generates new refresh token (rotation)
   └─ Old refresh token is revoked

4. Token Revocation
   ├─ Logout
   │  └─ Refresh token marked as revoked in DB
   ├─ Password change
   │  └─ All refresh tokens revoked
   └─ Security event
      └─ All refresh tokens revoked

5. Token Expiration
   ├─ Access Token expires → Client uses refresh token
   └─ Refresh Token expires → User must login again
```

## Scaling Considerations

```
┌────────────────────────────────────────────────────────────┐
│                   Horizontal Scaling                       │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Auth Service │  │ Auth Service │  │ Auth Service │    │
│  │  Instance 1  │  │  Instance 2  │  │  Instance 3  │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                 │             │
│         └─────────────────┼─────────────────┘             │
│                           │                               │
│                  ┌────────▼────────┐                      │
│                  │  Load Balancer  │                      │
│                  └────────┬────────┘                      │
│                           │                               │
│                  ┌────────▼────────┐                      │
│                  │   PostgreSQL    │                      │
│                  │  (Read Replicas)│                      │
│                  └─────────────────┘                      │
│                                                            │
│  Session Storage (for OAuth2 state):                      │
│  ┌──────────────┐                                         │
│  │    Redis     │ ◀─── Shared session store              │
│  └──────────────┘                                         │
└────────────────────────────────────────────────────────────┘
```

## Performance Optimization

1. **Database Indexing**
   - Indexes on frequently queried fields (email, token)
   - Composite indexes for joins

2. **Connection Pooling**
   - Reuse database connections
   - Configurable pool size

3. **Caching**
   - Cache user permissions
   - Cache role definitions
   - Use Redis for distributed caching

4. **Async Operations**
   - Non-blocking I/O
   - Promise-based operations

5. **Load Balancing**
   - Distribute requests across instances
   - Health check endpoints

## Monitoring Points

- Request rate per endpoint
- Failed authentication attempts
- Token generation rate
- Database connection pool usage
- API response times
- Error rates
- Active sessions
