# Secure-by-Design Web Application

## 🎯 Overview
A production-grade web application demonstrating security best practices from the ground up. This is NOT a deliberately vulnerable app - it showcases secure design patterns and defense-in-depth.

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   Client    │────▶ │  API Gateway │────▶ │  Services   │
│  (Browser)  │      │ Rate Limiter │      │   Layer     │
└─────────────┘      │   Security   │      └─────────────┘
                     │   Headers    │             │
                     └──────────────┘             ▼
                                          ┌─────────────┐
                                          │  Database   │
                                          │   (SQLite)  │
                                          └─────────────┘
```

## 🔐 Security Features

### 1. Authentication & Authorization
- **JWT Access Tokens** (15 min expiry)
- **Refresh Tokens** (7 days, rotating)
- **Password Hashing** (bcrypt, cost factor 12)
- **Role-Based Access Control** (Admin, User, Guest)
- **Session Management** (secure token storage)

### 2. API Security
- **Rate Limiting** (100 req/15min per IP)
- **Input Validation** (joi schema validation)
- **SQL Injection Prevention** (parameterized queries)
- **XSS Prevention** (output encoding, CSP)
- **CSRF Protection** (SameSite cookies)

### 3. Security Headers
- Content-Security-Policy
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict-Transport-Security
- X-XSS-Protection

### 4. Logging & Monitoring
- **Structured Logging** (Winston)
- **Security Events** (failed auth, suspicious activity)
- **Audit Trail** (all state changes)
- **PII Redaction** (passwords, tokens scrubbed)

### 5. Data Protection
- **Encryption at Rest** (sensitive fields)
- **TLS/HTTPS Only**
- **Secure Password Policy** (min 8 chars, complexity)
- **Input Sanitization** (DOMPurify for HTML)

## 🎭 Threat Model (STRIDE)

### Spoofing
**Threat**: Attacker impersonates legitimate user
- ✅ **Mitigation**: Strong password policy + bcrypt
- ✅ **Mitigation**: JWT signature verification (HS256)
- ✅ **Mitigation**: Refresh token rotation
- ⚠️ **Trade-off**: No MFA (out of scope) - document this gap

### Tampering
**Threat**: Attacker modifies data in transit or at rest
- ✅ **Mitigation**: HTTPS enforced (HSTS header)
- ✅ **Mitigation**: JWT signature validation
- ✅ **Mitigation**: Database integrity constraints
- ⚠️ **Trade-off**: No database-level encryption (SQLite limitation)

### Repudiation
**Threat**: User denies performing action
- ✅ **Mitigation**: Comprehensive audit logging
- ✅ **Mitigation**: Timestamps on all state changes
- ✅ **Mitigation**: User ID tracking in all operations
- ⚠️ **Trade-off**: Logs not cryptographically signed

### Information Disclosure
**Threat**: Unauthorized access to sensitive data
- ✅ **Mitigation**: RBAC on all endpoints
- ✅ **Mitigation**: Generic error messages (no stack traces)
- ✅ **Mitigation**: PII redaction in logs
- ✅ **Mitigation**: Security headers prevent data leaks
- ⚠️ **Trade-off**: Bearer tokens in headers (use HTTPS)

### Denial of Service
**Threat**: Attacker overwhelms system resources
- ✅ **Mitigation**: Rate limiting (express-rate-limit)
- ✅ **Mitigation**: Request size limits (body-parser)
- ✅ **Mitigation**: Connection timeouts
- ⚠️ **Trade-off**: No distributed rate limiting (single server)

### Elevation of Privilege
**Threat**: Attacker gains unauthorized permissions
- ✅ **Mitigation**: RBAC middleware on all routes
- ✅ **Mitigation**: Principle of least privilege
- ✅ **Mitigation**: No default admin accounts
- ✅ **Mitigation**: Input validation prevents privilege escalation

## 🚀 Quick Start

### Prerequisites
```bash
node >= 18.0.0
npm >= 9.0.0
```

### Installation
```bash
npm install
npm run init-db    # Initialize SQLite database
npm start          # Start server on port 3000
```

### Environment Variables
```env
NODE_ENV=production
JWT_SECRET=<strong-random-secret>
JWT_REFRESH_SECRET=<different-random-secret>
PORT=3000
LOG_LEVEL=info
```

## 📝 API Endpoints

### Public Endpoints
```
POST /api/auth/register    - Create new user account
POST /api/auth/login       - Authenticate user
POST /api/auth/refresh     - Refresh access token
```

### Protected Endpoints (User Role)
```
GET  /api/profile          - Get current user profile
PUT  /api/profile          - Update profile
GET  /api/data             - Fetch user data
```

### Admin Endpoints (Admin Role)
```
GET  /api/admin/users      - List all users
PUT  /api/admin/users/:id  - Modify user roles
GET  /api/admin/logs       - View audit logs
```

## 🔍 Testing Security

### 1. Authentication Tests
```bash
# Test failed login rate limiting
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"wrong@test.com","password":"wrong"}'
done

# Test JWT expiration
# (Wait 15 minutes and retry with old token)
```

### 2. Authorization Tests
```bash
# Try to access admin endpoint as regular user
curl -X GET http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer <user-token>"
# Expected: 403 Forbidden
```

### 3. Input Validation Tests
```bash
# Test SQL injection (should be blocked)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com OR 1=1--","password":"test"}'

# Test XSS (should be sanitized)
curl -X PUT http://localhost:3000/api/profile \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"<script>alert(1)</script>"}'
```

### 4. Rate Limiting Tests
```bash
# Flood endpoint (should hit rate limit at 100 req)
seq 1 150 | xargs -P10 -I{} curl http://localhost:3000/api/data
```

## 🐛 Discovered Issues & Fixes

### Issue #1: JWT Secret Exposure
**Found**: JWT secret logged during startup
**Impact**: Medium - Could lead to token forgery
**Fix**: Remove secret from logs, use environment validation
**Commit**: `abc123f`

### Issue #2: Timing Attack on Password Check
**Found**: bcrypt compare could leak timing information
**Impact**: Low - Requires many attempts
**Fix**: Added constant-time comparison wrapper
**Commit**: `def456a`

### Issue #3: CORS Misconfiguration
**Found**: Wildcard CORS allowed all origins
**Impact**: High - CSRF potential
**Fix**: Whitelist specific origins only
**Commit**: `ghi789b`

## ⚖️ Security Trade-offs

### 1. JWT vs Session Cookies
**Chosen**: JWT with refresh tokens
**Pros**: Stateless, scalable, mobile-friendly
**Cons**: Cannot invalidate tokens immediately
**Mitigation**: Short expiry (15 min) + refresh rotation

### 2. bcrypt vs Argon2
**Chosen**: bcrypt (cost factor 12)
**Pros**: Battle-tested, widely supported
**Cons**: Slightly less memory-hard than Argon2
**Rationale**: Better ecosystem support in Node.js

### 3. SQLite vs PostgreSQL
**Chosen**: SQLite for demo
**Pros**: Zero config, portable
**Cons**: No advanced security features
**Production**: Use PostgreSQL with row-level security

### 4. In-Memory Rate Limiting
**Chosen**: Single-server rate limiting
**Pros**: Simple, fast
**Cons**: Doesn't scale across instances
**Production**: Use Redis for distributed rate limiting

### 5. No MFA
**Chosen**: Password-only authentication
**Rationale**: Scope limitation for demo
**Production**: Add TOTP or WebAuthn

## 📊 Security Metrics

- **Password Policy**: 8+ chars, uppercase, lowercase, number
- **Token Expiry**: Access 15min, Refresh 7 days
- **Rate Limit**: 100 requests per 15 minutes
- **Bcrypt Cost**: 12 rounds (~250ms per hash)
- **Max Request Size**: 10kb

## 🔧 CI/CD Security Checks

### Automated Scans
```yaml
- npm audit (dependency vulnerabilities)
- eslint-plugin-security (code patterns)
- helmet check (security headers)
- OWASP ZAP baseline scan
```

### Pre-commit Hooks
```bash
- Secret scanning (detect committed secrets)
- Lint checks
- Unit test coverage
```

## 📚 References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

## 🎓 What This Demonstrates

1. **Security-First Design**: Secure defaults from Day 1
2. **Defense in Depth**: Multiple layers of protection
3. **Threat Modeling**: STRIDE analysis drives decisions
4. **Trade-off Documentation**: Transparent about limitations
5. **Attack Surface Awareness**: Self-testing for vulnerabilities
6. **Production Readiness**: Real-world patterns, not academic

---

**Author**: [Your Name]  
**Purpose**: AppSec Portfolio Project  
**License**: MIT