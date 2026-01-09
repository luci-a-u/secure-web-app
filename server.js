// ===== server.js =====
// Secure-by-Design Web Application
// Production-grade security patterns demonstration

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const winston = require('winston');
const Joi = require('joi');
const crypto = require('crypto');

// ============================================
// CONFIGURATION & CONSTANTS
// ============================================

const config = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || crypto.randomBytes(32).toString('hex'),
  jwtExpiry: '15m',
  refreshExpiry: '7d',
  bcryptRounds: 12,
  env: process.env.NODE_ENV || 'development'
};

// Security: Warn if using default secrets in production
if (config.env === 'production' && !process.env.JWT_SECRET) {
  console.error('⚠️  WARNING: Using default JWT secret in production!');
}

// ============================================
// LOGGING SETUP
// ============================================

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'secure-web-app' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.File({ filename: 'security.log', level: 'warn' })
  ]
});

if (config.env !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// PII Redaction - Remove sensitive data from logs
const redactPII = (obj) => {
  const redacted = { ...obj };
  const sensitiveFields = ['password', 'token', 'refreshToken', 'authorization'];
  sensitiveFields.forEach(field => {
    if (redacted[field]) redacted[field] = '[REDACTED]';
  });
  return redacted;
};

// ============================================
// DATABASE SETUP
// ============================================

const db = new sqlite3.Database('./secure_app.db', (err) => {
  if (err) {
    logger.error('Database connection failed', { error: err.message });
    process.exit(1);
  }
  logger.info('Connected to SQLite database');
});

// Initialize database schema
db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user' CHECK(role IN ('admin', 'user', 'guest')),
      name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Refresh tokens table
  db.run(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Audit log table
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      resource TEXT,
      ip_address TEXT,
      user_agent TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      details TEXT
    )
  `);

  // User data table (for demo purposes)
  db.run(`
    CREATE TABLE IF NOT EXISTS user_data (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  logger.info('Database schema initialized');
});

// ============================================
// EXPRESS APP SETUP
// ============================================

const app = express();

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Body parsing with size limits (DoS prevention)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Request logging middleware
app.use((req, res, next) => {
  const logData = {
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('user-agent')
  };
  logger.info('Incoming request', redactPII(logData));
  next();
});

// Global rate limiter (DoS prevention)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', { ip: req.ip, path: req.path });
    res.status(429).json({ error: 'Too many requests, please try again later.' });
  }
});

app.use('/api/', globalLimiter);

// Strict rate limiter for auth endpoints (Brute force prevention)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Only 5 attempts per 15 minutes
  skipSuccessfulRequests: true,
  message: { error: 'Too many authentication attempts, please try again later.' }
});

// ============================================
// VALIDATION SCHEMAS
// ============================================

const schemas = {
  register: Joi.object({
    email: Joi.string().email().required().max(255),
    password: Joi.string().min(8).max(128).required()
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .messages({
        'string.pattern.base': 'Password must contain uppercase, lowercase, and number'
      }),
    name: Joi.string().min(2).max(100).optional()
  }),

  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  }),

  updateProfile: Joi.object({
    name: Joi.string().min(2).max(100).optional()
  }),

  createData: Joi.object({
    content: Joi.string().max(1000).required()
  })
};

// Validation middleware factory
const validate = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body, { abortEarly: false });
    if (error) {
      const errors = error.details.map(detail => detail.message);
      logger.warn('Validation failed', { errors, body: redactPII(req.body) });
      return res.status(400).json({ error: 'Validation failed', details: errors });
    }
    next();
  };
};

// ============================================
// AUDIT LOGGING
// ============================================

const auditLog = (userId, action, resource, req, details = null) => {
  const stmt = db.prepare(`
    INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, details)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  
  stmt.run(
    userId,
    action,
    resource,
    req.ip,
    req.get('user-agent'),
    details ? JSON.stringify(details) : null
  );
  
  stmt.finalize();
  
  logger.info('Audit log', { userId, action, resource });
};

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn('No token provided', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, config.jwtSecret, (err, user) => {
    if (err) {
      logger.warn('Invalid token', { ip: req.ip, error: err.message });
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Authorization middleware factory
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      logger.warn('Insufficient permissions', { 
        userId: req.user.id, 
        role: req.user.role, 
        required: allowedRoles 
      });
      auditLog(req.user.id, 'ACCESS_DENIED', req.path, req);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

// ============================================
// HELPER FUNCTIONS
// ============================================

const generateTokens = (userId, email, role) => {
  const accessToken = jwt.sign(
    { id: userId, email, role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiry }
  );

  const refreshToken = jwt.sign(
    { id: userId, type: 'refresh' },
    config.jwtRefreshSecret,
    { expiresIn: config.refreshExpiry }
  );

  return { accessToken, refreshToken };
};

const storeRefreshToken = (userId, refreshToken) => {
  return new Promise((resolve, reject) => {
    // Hash the refresh token before storing (defense in depth)
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    db.run(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
      [userId, tokenHash, expiresAt.toISOString()],
      (err) => {
        if (err) reject(err);
        else resolve();
      }
    );
  });
};

// ============================================
// ROUTES - AUTHENTICATION
// ============================================

// User Registration
app.post('/api/auth/register', authLimiter, validate(schemas.register), async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Check if user exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        logger.error('Database error during registration', { error: err.message });
        return res.status(500).json({ error: 'Registration failed' });
      }

      if (row) {
        logger.warn('Registration attempted with existing email', { email });
        return res.status(409).json({ error: 'Email already registered' });
      }

      // Hash password
      const passwordHash = await bcrypt.hash(password, config.bcryptRounds);

      // Create user
      db.run(
        'INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)',
        [email, passwordHash, name || null, 'user'],
        function(err) {
          if (err) {
            logger.error('Failed to create user', { error: err.message });
            return res.status(500).json({ error: 'Registration failed' });
          }

          const userId = this.lastID;
          auditLog(userId, 'USER_REGISTERED', '/api/auth/register', req);
          
          logger.info('User registered successfully', { userId, email });
          
          res.status(201).json({ 
            message: 'User registered successfully',
            userId 
          });
        }
      );
    });
  } catch (error) {
    logger.error('Registration error', { error: error.message });
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User Login
app.post('/api/auth/login', authLimiter, validate(schemas.login), async (req, res) => {
  try {
    const { email, password } = req.body;

    db.get(
      'SELECT id, email, password_hash, role, name FROM users WHERE email = ?',
      [email],
      async (err, user) => {
        if (err) {
          logger.error('Database error during login', { error: err.message });
          return res.status(500).json({ error: 'Login failed' });
        }

        // Generic error message to prevent user enumeration
        if (!user) {
          logger.warn('Login attempted with non-existent email', { email, ip: req.ip });
          auditLog(null, 'LOGIN_FAILED', '/api/auth/login', req, { reason: 'invalid_credentials' });
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
          logger.warn('Login failed - incorrect password', { userId: user.id, ip: req.ip });
          auditLog(user.id, 'LOGIN_FAILED', '/api/auth/login', req, { reason: 'invalid_password' });
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate tokens
        const { accessToken, refreshToken } = generateTokens(user.id, user.email, user.role);

        // Store refresh token
        await storeRefreshToken(user.id, refreshToken);

        auditLog(user.id, 'LOGIN_SUCCESS', '/api/auth/login', req);
        logger.info('User logged in successfully', { userId: user.id });

        res.json({
          accessToken,
          refreshToken,
          user: {
            id: user.id,
            email: user.email,
            role: user.role,
            name: user.name
          }
        });
      }
    );
  } catch (error) {
    logger.error('Login error', { error: error.message });
    res.status(500).json({ error: 'Login failed' });
  }
});

// Refresh Token
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }

    // Verify refresh token
    jwt.verify(refreshToken, config.jwtRefreshSecret, async (err, decoded) => {
      if (err) {
        logger.warn('Invalid refresh token', { error: err.message });
        return res.status(403).json({ error: 'Invalid refresh token' });
      }

      // Check if token exists in database
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      
      db.get(
        'SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = ?',
        [tokenHash],
        (err, row) => {
          if (err || !row) {
            logger.warn('Refresh token not found', { userId: decoded.id });
            return res.status(403).json({ error: 'Invalid refresh token' });
          }

          // Check expiration
          if (new Date(row.expires_at) < new Date()) {
            logger.warn('Refresh token expired', { userId: decoded.id });
            return res.status(403).json({ error: 'Refresh token expired' });
          }

          // Get user info
          db.get(
            'SELECT id, email, role FROM users WHERE id = ?',
            [row.user_id],
            async (err, user) => {
              if (err || !user) {
                return res.status(403).json({ error: 'Invalid refresh token' });
              }

              // Generate new tokens (token rotation)
              const newTokens = generateTokens(user.id, user.email, user.role);

              // Delete old refresh token
              db.run('DELETE FROM refresh_tokens WHERE token_hash = ?', [tokenHash]);

              // Store new refresh token
              await storeRefreshToken(user.id, newTokens.refreshToken);

              auditLog(user.id, 'TOKEN_REFRESHED', '/api/auth/refresh', req);
              
              res.json({
                accessToken: newTokens.accessToken,
                refreshToken: newTokens.refreshToken
              });
            }
          );
        }
      );
    });
  } catch (error) {
    logger.error('Token refresh error', { error: error.message });
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ============================================
// ROUTES - USER PROFILE
// ============================================

// Get Profile
app.get('/api/profile', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, email, role, name, created_at FROM users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({ user });
    }
  );
});

// Update Profile
app.put('/api/profile', authenticateToken, validate(schemas.updateProfile), (req, res) => {
  const { name } = req.body;

  db.run(
    'UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [name, req.user.id],
    function(err) {
      if (err) {
        logger.error('Profile update failed', { error: err.message, userId: req.user.id });
        return res.status(500).json({ error: 'Update failed' });
      }

      auditLog(req.user.id, 'PROFILE_UPDATED', '/api/profile', req);
      res.json({ message: 'Profile updated successfully' });
    }
  );
});

// ============================================
// ROUTES - USER DATA (Protected)
// ============================================

// Get User Data
app.get('/api/data', authenticateToken, requireRole('user', 'admin'), (req, res) => {
  db.all(
    'SELECT id, content, created_at FROM user_data WHERE user_id = ?',
    [req.user.id],
    (err, rows) => {
      if (err) {
        logger.error('Failed to fetch data', { error: err.message, userId: req.user.id });
        return res.status(500).json({ error: 'Failed to fetch data' });
      }
      res.json({ data: rows });
    }
  );
});

// Create User Data
app.post('/api/data', authenticateToken, requireRole('user', 'admin'), validate(schemas.createData), (req, res) => {
  const { content } = req.body;

  db.run(
    'INSERT INTO user_data (user_id, content) VALUES (?, ?)',
    [req.user.id, content],
    function(err) {
      if (err) {
        logger.error('Failed to create data', { error: err.message, userId: req.user.id });
        return res.status(500).json({ error: 'Failed to create data' });
      }

      auditLog(req.user.id, 'DATA_CREATED', '/api/data', req);
      res.status(201).json({ message: 'Data created successfully', id: this.lastID });
    }
  );
});

// ============================================
// ROUTES - ADMIN
// ============================================

// List All Users
app.get('/api/admin/users', authenticateToken, requireRole('admin'), (req, res) => {
  db.all(
    'SELECT id, email, role, name, created_at FROM users',
    [],
    (err, rows) => {
      if (err) {
        logger.error('Failed to fetch users', { error: err.message });
        return res.status(500).json({ error: 'Failed to fetch users' });
      }
      auditLog(req.user.id, 'ADMIN_LIST_USERS', '/api/admin/users', req);
      res.json({ users: rows });
    }
  );
});

// Update User Role
app.put('/api/admin/users/:id', authenticateToken, requireRole('admin'), (req, res) => {
  const { role } = req.body;
  const targetUserId = req.params.id;

  if (!['admin', 'user', 'guest'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  db.run(
    'UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [role, targetUserId],
    function(err) {
      if (err) {
        logger.error('Failed to update user role', { error: err.message });
        return res.status(500).json({ error: 'Update failed' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      auditLog(req.user.id, 'ADMIN_UPDATE_ROLE', `/api/admin/users/${targetUserId}`, req, { newRole: role });
      res.json({ message: 'User role updated successfully' });
    }
  );
});

// View Audit Logs
app.get('/api/admin/logs', authenticateToken, requireRole('admin'), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  
  db.all(
    'SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?',
    [limit],
    (err, rows) => {
      if (err) {
        logger.error('Failed to fetch logs', { error: err.message });
        return res.status(500).json({ error: 'Failed to fetch logs' });
      }
      res.json({ logs: rows });
    }
  );
});

// ============================================
// ERROR HANDLING
// ============================================

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global Error Handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { 
    error: err.message, 
    stack: err.stack,
    path: req.path 
  });
  
  // Don't leak error details in production
  const message = config.env === 'production' 
    ? 'Internal server error' 
    : err.message;
    
  res.status(500).json({ error: message });
});

// ============================================
// SERVER START
// ============================================

const server = app.listen(config.port, () => {
  logger.info(`🔒 Secure Web App started on port ${config.port}`);
  logger.info(`Environment: ${config.env}`);
  logger.info('Security features enabled: Helmet, Rate Limiting, RBAC, JWT Auth');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
    db.close(() => {
      logger.info('Database connection closed');
      process.exit(0);
    });
  });
});

module.exports = app; // For testing