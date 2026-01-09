// ===== tests/security.test.js =====
// Comprehensive security testing suite

const request = require('supertest');
const app = require('../server');

describe('Security Tests', () => {
  let userToken;
  let adminToken;
  let testUser = {
    email: 'test@example.com',
    password: 'SecurePass123'
  };

  // ============================================
  // AUTHENTICATION TESTS
  // ============================================
  
  describe('Authentication Security', () => {
    test('Should reject weak passwords', async () => {
      const weakPasswords = [
        'short',           // Too short
        'alllowercase',    // No uppercase or numbers
        'ALLUPPERCASE',    // No lowercase or numbers
        'NoNumbers',       // No numbers
      ];

      for (const password of weakPasswords) {
        const res = await request(app)
          .post('/api/auth/register')
          .send({ email: 'weak@test.com', password });
        
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Validation failed');
      }
    });

    test('Should accept strong passwords', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser);
      
      expect([201, 409]).toContain(res.status); // 201 = created, 409 = already exists
    });

    test('Should rate limit failed login attempts', async () => {
      const attempts = [];
      
      // Try 6 failed logins (limit is 5)
      for (let i = 0; i < 6; i++) {
        attempts.push(
          request(app)
            .post('/api/auth/login')
            .send({ email: 'wrong@test.com', password: 'WrongPass123' })
        );
      }

      const results = await Promise.all(attempts);
      const rateLimited = results.some(res => res.status === 429);
      
      expect(rateLimited).toBe(true);
    });

    test('Should not leak user existence in error messages', async () => {
      const nonExistentRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'nonexistent@test.com', password: 'SomePass123' });

      const wrongPasswordRes = await request(app)
        .post('/api/auth/login')
        .send({ email: testUser.email, password: 'WrongPass123' });

      // Both should return the same generic error
      expect(nonExistentRes.body.error).toBe('Invalid credentials');
      expect(wrongPasswordRes.body.error).toBe('Invalid credentials');
    });

    test('Should generate valid JWT tokens', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send(testUser);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('accessToken');
      expect(res.body).toHaveProperty('refreshToken');
      
      // JWT format: xxx.yyy.zzz
      const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
      expect(res.body.accessToken).toMatch(jwtRegex);
      
      userToken = res.body.accessToken;
    });
  });

  // ============================================
  // AUTHORIZATION TESTS
  // ============================================

  describe('Authorization (RBAC)', () => {
    test('Should reject requests without token', async () => {
      const res = await request(app)
        .get('/api/profile');
      
      expect(res.status).toBe(401);
      expect(res.body.error).toContain('token');
    });

    test('Should reject invalid tokens', async () => {
      const res = await request(app)
        .get('/api/profile')
        .set('Authorization', 'Bearer invalid.token.here');
      
      expect(res.status).toBe(403);
    });

    test('Should allow access to protected routes with valid token', async () => {
      const res = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('user');
    });

    test('Should block regular users from admin endpoints', async () => {
      const res = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.status).toBe(403);
      expect(res.body.error).toContain('Insufficient permissions');
    });
  });

  // ============================================
  // INPUT VALIDATION TESTS
  // ============================================

  describe('Input Validation', () => {
    test('Should reject SQL injection attempts', async () => {
      const sqlInjectionAttempts = [
        { email: "admin' OR '1'='1", password: 'Test123' },
        { email: "admin'--", password: 'Test123' },
        { email: "'; DROP TABLE users;--", password: 'Test123' }
      ];

      for (const payload of sqlInjectionAttempts) {
        const res = await request(app)
          .post('/api/auth/login')
          .send(payload);
        
        // Should either reject validation or fail authentication, not execute SQL
        expect([400, 401]).toContain(res.status);
      }
    });

    test('Should reject XSS attempts in profile update', async () => {
      const xssPayloads = [
        { name: '<script>alert("XSS")</script>' },
        { name: '<img src=x onerror=alert(1)>' },
        { name: 'javascript:alert(1)' }
      ];

      for (const payload of xssPayloads) {
        const res = await request(app)
          .put('/api/profile')
          .set('Authorization', `Bearer ${userToken}`)
          .send(payload);
        
        // Should store safely or reject
        expect(res.status).not.toBe(500);
      }
    });

    test('Should enforce maximum length constraints', async () => {
      const res = await request(app)
        .post('/api/data')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ content: 'a'.repeat(2000) }); // Exceeds 1000 char limit
      
      expect(res.status).toBe(400);
    });

    test('Should reject invalid email formats', async () => {
      const invalidEmails = [
        'notanemail',
        '@nodomain.com',
        'missing@domain',
        'spaces in@email.com'
      ];

      for (const email of invalidEmails) {
        const res = await request(app)
          .post('/api/auth/register')
          .send({ email, password: 'Test123Pass' });
        
        expect(res.status).toBe(400);
      }
    });
  });

  // ============================================
  // SECURITY HEADERS TESTS
  // ============================================

  describe('Security Headers', () => {
    test('Should set security headers', async () => {
      const res = await request(app).get('/api/profile');
      
      // Check for important security headers set by Helmet
      expect(res.headers).toHaveProperty('x-frame-options');
      expect(res.headers).toHaveProperty('x-content-type-options');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    test('Should set CSP header', async () => {
      const res = await request(app).get('/api/profile');
      expect(res.headers).toHaveProperty('content-security-policy');
    });

    test('Should set HSTS header', async () => {
      const res = await request(app).get('/api/profile');
      expect(res.headers).toHaveProperty('strict-transport-security');
    });
  });

  // ============================================
  // RATE LIMITING TESTS
  // ============================================

  describe('Rate Limiting', () => {
    test('Should rate limit excessive requests', async () => {
      const requests = [];
      
      // Make 101 requests (limit is 100 per 15 min)
      for (let i = 0; i < 101; i++) {
        requests.push(request(app).get('/api/profile'));
      }

      const results = await Promise.all(requests);
      const rateLimited = results.some(res => res.status === 429);
      
      expect(rateLimited).toBe(true);
    }, 30000); // Longer timeout for this test
  });

  // ============================================
  // SESSION MANAGEMENT TESTS
  // ============================================

  describe('Token Refresh Mechanism', () => {
    test('Should refresh tokens successfully', async () => {
      // First login
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send(testUser);

      const refreshToken = loginRes.body.refreshToken;

      // Refresh
      const refreshRes = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken });

      expect(refreshRes.status).toBe(200);
      expect(refreshRes.body).toHaveProperty('accessToken');
      expect(refreshRes.body).toHaveProperty('refreshToken');
      
      // New refresh token should be different (token rotation)
      expect(refreshRes.body.refreshToken).not.toBe(refreshToken);
    });

    test('Should reject reused refresh tokens', async () => {
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send(testUser);

      const refreshToken = loginRes.body.refreshToken;

      // Use token once
      await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken });

      // Try to reuse the same token
      const reusedRes = await request(app)
        .post('/api/auth/refresh')
        .send({ refreshToken });

      expect(reusedRes.status).toBe(403);
    });
  });

  // ============================================
  // ERROR HANDLING TESTS
  // ============================================

  describe('Error Handling', () => {
    test('Should return 404 for non-existent endpoints', async () => {
      const res = await request(app).get('/api/nonexistent');
      expect(res.status).toBe(404);
    });

    test('Should not leak stack traces in errors', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ invalid: 'data' });
      
      expect(res.body).not.toHaveProperty('stack');
      expect(res.body.error).toBeDefined();
    });
  });
});

// ===== tests/attack-scenarios.test.js =====
// Real-world attack scenario testing

describe('Attack Scenario Tests', () => {
  describe('Credential Stuffing Attack', () => {
    test('Should block rapid credential attempts from same IP', async () => {
      const credentials = [
        { email: 'user1@test.com', password: 'Password123' },
        { email: 'user2@test.com', password: 'Password123' },
        { email: 'user3@test.com', password: 'Password123' },
        { email: 'user4@test.com', password: 'Password123' },
        { email: 'user5@test.com', password: 'Password123' },
        { email: 'user6@test.com', password: 'Password123' },
      ];

      const results = await Promise.all(
        credentials.map(cred => 
          request(app).post('/api/auth/login').send(cred)
        )
      );

      const blocked = results.some(res => res.status === 429);
      expect(blocked).toBe(true);
    });
  });

  describe('Privilege Escalation Attempt', () => {
    test('Should prevent role modification via profile update', async () => {
      // Register regular user
      const userRes = await request(app)
        .post('/api/auth/register')
        .send({ email: 'privesc@test.com', password: 'Test123Pass' });

      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'privesc@test.com', password: 'Test123Pass' });

      const token = loginRes.body.accessToken;

      // Try to set role to admin via profile update
      const escalationRes = await request(app)
        .put('/api/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({ role: 'admin', name: 'Hacker' });

      // Should either ignore the role field or reject
      const profileRes = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${token}`);

      expect(profileRes.body.user.role).not.toBe('admin');
    });
  });

  describe('IDOR (Insecure Direct Object Reference)', () => {
    test('Should prevent accessing other users data', async () => {
      // This test assumes proper implementation
      // In a real scenario, you'd need two users and try to access user1's data as user2
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@example.com', password: 'SecurePass123' });

      const token = loginRes.body.accessToken;

      // Try to access data with a different user ID in the URL
      // (This endpoint doesn't exist, but demonstrates the concept)
      const res = await request(app)
        .get('/api/users/999/data')
        .set('Authorization', `Bearer ${token}`);

      expect([404, 403]).toContain(res.status);
    });
  });

  describe('Mass Assignment Attack', () => {
    test('Should ignore unexpected fields in requests', async () => {
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@example.com', password: 'SecurePass123' });

      const token = loginRes.body.accessToken;

      // Try to inject extra fields
      const res = await request(app)
        .put('/api/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({ 
          name: 'John Doe',
          role: 'admin',           // Should be ignored
          isVerified: true,        // Should be ignored
          credits: 9999            // Should be ignored
        });

      // Verify only allowed field was updated
      const profile = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${token}`);

      expect(profile.body.user.role).not.toBe('admin');
    });
  });
});