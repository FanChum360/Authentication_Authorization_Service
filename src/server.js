const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

// Import routes
const authRoutes = require('./routes/authRoutes');
const oauth2Routes = require('./routes/oauth2Routes');

// Import middleware
const { apiLimiter } = require('./middleware/rateLimiter');

const app = express();

// Security middleware
if (process.env.ENABLE_HELMET !== 'false') {
  app.use(helmet());
}

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN || '*',
  credentials: process.env.CORS_CREDENTIALS === 'true',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

if (process.env.ENABLE_CORS !== 'false') {
  app.use(cors(corsOptions));
}

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Trust proxy (for rate limiting and IP detection when behind load balancer)
app.set('trust proxy', 1);

// Apply rate limiting to all routes
app.use(apiLimiter);

// Request logging middleware (simple version)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(
      `${new Date().toISOString()} ${req.method} ${req.path} ${res.statusCode} ${duration}ms`
    );
  });
  next();
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Authentication & Authorization Service',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      auth: '/api/auth',
      oauth2: '/oauth',
      health: '/api/auth/health',
      discovery: '/.well-known/oauth-authorization-server',
    },
  });
});

// Mount routes
app.use('/api/auth', authRoutes);
app.use('/oauth', oauth2Routes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource does not exist',
    path: req.path,
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  // Don't leak error details in production
  const message =
    process.env.NODE_ENV === 'production'
      ? 'An internal server error occurred'
      : err.message;

  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });
});

// Start server
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

app.listen(PORT, () => {
  console.log('\n' + '='.repeat(50));
  console.log('🔐 Auth Service Started');
  console.log('='.repeat(50));
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Server: http://${HOST}:${PORT}`);
  console.log(`Health: http://${HOST}:${PORT}/api/auth/health`);
  console.log(`Discovery: http://${HOST}:${PORT}/.well-known/oauth-authorization-server`);
  console.log('='.repeat(50) + '\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\nSIGINT received, shutting down gracefully...');
  process.exit(0);
});

module.exports = app;
