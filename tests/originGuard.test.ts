import { describe, it, expect, beforeEach, vi } from 'vitest';

// The module reads process.env at call time, so we can override per-test
const GUARD_PATH = '../api/shared/originGuard.js';

function buildMockReq(overrides = {}) {
  return {
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
    ...overrides,
  };
}

function buildMockRes() {
  const res = {
    _status: null,
    _json: null,
    _headers: {},
    status(code) {
      res._status = code;
      return res;
    },
    json(body) {
      res._json = body;
      return res;
    },
    setHeader(key, value) {
      res._headers[key] = value;
    },
  };
  return res;
}

describe('originGuard', () => {
  // Fresh import for each test to avoid module-level caching issues
  let validateRequestOrigin;
  let checkRequestRateLimit;
  let __resetRateLimitState;

  beforeEach(async () => {
    // Reset rate limit state between tests
    const mod = await import(GUARD_PATH);
    validateRequestOrigin = mod.validateRequestOrigin;
    checkRequestRateLimit = mod.checkRequestRateLimit;
    __resetRateLimitState = mod.__resetRateLimitState;
    __resetRateLimitState();
  });

  // -----------------------------------------------------------------------
  // Origin validation
  // -----------------------------------------------------------------------

  describe('validateRequestOrigin', () => {
    it('allows all origins when NODE_ENV is not production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const req = buildMockReq({
        headers: { origin: 'https://evil-site.com' },
      });
      const res = buildMockRes();

      const blocked = validateRequestOrigin(req, res);
      expect(blocked).toBe(false);
      expect(res._status).toBeNull();

      process.env.NODE_ENV = originalEnv;
    });

    it('blocks requests from unknown origins in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const req = buildMockReq({
        headers: { origin: 'https://attacker.com' },
      });
      const res = buildMockRes();

      const blocked = validateRequestOrigin(req, res);
      expect(blocked).toBe(true);
      expect(res._status).toBe(403);
      expect(res._json.code).toBe('ORIGIN_NOT_ALLOWED');

      process.env.NODE_ENV = originalEnv;
    });

    it('allows requests from configured origins in production', () => {
      const originalEnv = process.env.NODE_ENV;
      const originalOrigins = process.env.API_ALLOWED_ORIGINS;
      process.env.NODE_ENV = 'production';
      process.env.API_ALLOWED_ORIGINS = 'https://hushhtech.com,https://www.hushhtech.com';

      const req = buildMockReq({
        headers: { origin: 'https://hushhtech.com' },
      });
      const res = buildMockRes();

      const blocked = validateRequestOrigin(req, res);
      expect(blocked).toBe(false);
      expect(res._headers['Access-Control-Allow-Origin']).toBe('https://hushhtech.com');
      expect(res._headers['Vary']).toBe('Origin');

      process.env.NODE_ENV = originalEnv;
      if (originalOrigins !== undefined) {
        process.env.API_ALLOWED_ORIGINS = originalOrigins;
      } else {
        delete process.env.API_ALLOWED_ORIGINS;
      }
    });

    it('falls back to Referer header when Origin is missing', () => {
      const originalEnv = process.env.NODE_ENV;
      const originalOrigins = process.env.API_ALLOWED_ORIGINS;
      process.env.NODE_ENV = 'production';
      process.env.API_ALLOWED_ORIGINS = 'https://hushhtech.com';

      const req = buildMockReq({
        headers: { referer: 'https://hushhtech.com/investor/some-slug?tab=profile' },
      });
      const res = buildMockRes();

      const blocked = validateRequestOrigin(req, res);
      expect(blocked).toBe(false);

      process.env.NODE_ENV = originalEnv;
      if (originalOrigins !== undefined) {
        process.env.API_ALLOWED_ORIGINS = originalOrigins;
      } else {
        delete process.env.API_ALLOWED_ORIGINS;
      }
    });

    it('blocks requests with no origin and no referer in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const req = buildMockReq({ headers: {} });
      const res = buildMockRes();

      const blocked = validateRequestOrigin(req, res);
      expect(blocked).toBe(true);
      expect(res._status).toBe(403);

      process.env.NODE_ENV = originalEnv;
    });
  });

  // -----------------------------------------------------------------------
  // Rate limiting
  // -----------------------------------------------------------------------

  describe('checkRequestRateLimit', () => {
    it('allows requests within the configured limit', () => {
      const req = buildMockReq({
        headers: { 'x-forwarded-for': '10.0.0.1' },
      });
      const res = buildMockRes();

      const blocked = checkRequestRateLimit(req, res, {
        windowMs: 60_000,
        maxRequests: 5,
      });
      expect(blocked).toBe(false);
      expect(res._status).toBeNull();
    });

    it('returns 429 when the per-IP limit is exceeded', () => {
      const req = buildMockReq({
        headers: { 'x-forwarded-for': '10.0.0.2' },
      });

      // Exhaust the limit
      for (let i = 0; i < 3; i++) {
        const res = buildMockRes();
        checkRequestRateLimit(req, res, { windowMs: 60_000, maxRequests: 3 });
      }

      // The 4th request should be blocked
      const res = buildMockRes();
      const blocked = checkRequestRateLimit(req, res, {
        windowMs: 60_000,
        maxRequests: 3,
      });

      expect(blocked).toBe(true);
      expect(res._status).toBe(429);
      expect(res._json.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(res._headers['Retry-After']).toBe('60');
    });

    it('does not rate-limit different IPs against each other', () => {
      const req1 = buildMockReq({
        headers: { 'x-forwarded-for': '10.0.0.3' },
      });
      const req2 = buildMockReq({
        headers: { 'x-forwarded-for': '10.0.0.4' },
      });

      // Exhaust the limit for IP 10.0.0.3
      for (let i = 0; i < 2; i++) {
        checkRequestRateLimit(req1, buildMockRes(), {
          windowMs: 60_000,
          maxRequests: 2,
        });
      }

      // IP 10.0.0.4 should still be allowed
      const res = buildMockRes();
      const blocked = checkRequestRateLimit(req2, res, {
        windowMs: 60_000,
        maxRequests: 2,
      });
      expect(blocked).toBe(false);
    });

    it('falls back to socket.remoteAddress when x-forwarded-for is missing', () => {
      const req = buildMockReq({
        headers: {},
        socket: { remoteAddress: '192.168.1.99' },
      });
      const res = buildMockRes();

      const blocked = checkRequestRateLimit(req, res, {
        windowMs: 60_000,
        maxRequests: 5,
      });
      expect(blocked).toBe(false);
    });
  });
});
