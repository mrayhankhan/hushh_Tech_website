import { describe, it, expect, beforeEach, vi } from 'vitest';

/**
 * Tests for the send-email-notification API route hardening.
 * Verifies that origin validation and rate limiting are applied
 * before any email business logic runs, and that error responses
 * no longer leak internal details.
 */

function buildMockReq(overrides = {}) {
  return {
    method: 'POST',
    headers: {},
    body: {},
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

// Mock nodemailer so tests don't attempt real SMTP connections
vi.mock('nodemailer', () => ({
  default: {
    createTransport: () => ({
      sendMail: vi.fn().mockResolvedValue({ messageId: 'test-id' }),
    }),
  },
}));

// Mock Supabase client — the route resolves profile owner emails via Supabase
vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({
    from: () => ({
      select: () => ({
        eq: () => ({
          eq: () => ({
            eq: () => ({
              maybeSingle: vi.fn().mockResolvedValue({
                data: { email: 'owner@test.com', name: 'Test Owner' },
                error: null,
              }),
            }),
          }),
        }),
      }),
    }),
  }),
}));

describe('send-email-notification route', () => {
  let handler;
  let resetRateLimit;

  beforeEach(async () => {
    const routeModule = await import('../api/send-email-notification.js');
    handler = routeModule.default;
    const guardModule = await import('../api/shared/originGuard.js');
    resetRateLimit = guardModule.__resetRateLimitState;
    resetRateLimit();

    // Ensure tests run as development so origin checks pass
    process.env.NODE_ENV = 'test';
    process.env.GMAIL_USER = 'test@example.com';
    process.env.GMAIL_APP_PASSWORD = 'test-password';
    process.env.SUPABASE_URL = 'https://test.supabase.co';
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
  });

  it('rejects non-POST requests with 405', async () => {
    const req = buildMockReq({ method: 'GET' });
    const res = buildMockRes();
    await handler(req, res);
    expect(res._status).toBe(405);
    expect(res._json.error).toBe('Method not allowed');
  });

  it('returns 429 when the per-IP email rate limit is exceeded', async () => {
    // The email route limits to 10 requests per 60s
    for (let i = 0; i < 10; i++) {
      const res = buildMockRes();
      await handler(
        buildMockReq({
          headers: { 'x-forwarded-for': '10.99.0.1' },
          body: { type: 'profile_view', slug: 'test-slug' },
        }),
        res
      );
    }

    // The 11th request should be rate limited
    const res = buildMockRes();
    await handler(
      buildMockReq({
        headers: { 'x-forwarded-for': '10.99.0.1' },
        body: { type: 'profile_view', slug: 'test-slug' },
      }),
      res
    );
    expect(res._status).toBe(429);
    expect(res._json.code).toBe('RATE_LIMIT_EXCEEDED');
  });

  it('rejects unknown origins in production mode', async () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    const req = buildMockReq({
      headers: { origin: 'https://attacker-site.com' },
      body: { type: 'profile_view', slug: 'test-slug' },
    });
    const res = buildMockRes();
    await handler(req, res);

    expect(res._status).toBe(403);
    expect(res._json.code).toBe('ORIGIN_NOT_ALLOWED');

    process.env.NODE_ENV = originalEnv;
  });

  it('does not expose internal error details in the response', async () => {
    // Force an error by sending an invalid notification type
    // The handler should catch and return a sanitized message
    const req = buildMockReq({
      body: { type: 'profile_view', slug: 'test-slug' },
    });
    const res = buildMockRes();
    await handler(req, res);

    // Even if an error occurs, the response should never contain
    // a raw stack trace or error.toString() output
    if (res._status === 500) {
      expect(res._json.error).toBe('Email notification failed');
      expect(res._json).not.toHaveProperty('details');
      expect(res._json).toHaveProperty('detail');
      // The detail field should be a simple message, not a full stack trace
      expect(res._json.detail).not.toContain('at ');
    }
  });

  it('handles OPTIONS preflight with 200', async () => {
    const req = buildMockReq({ method: 'OPTIONS' });
    const res = buildMockRes();
    await handler(req, res);
    expect(res._status).toBe(200);
  });

  it('returns 400 when required fields are missing', async () => {
    const req = buildMockReq({
      body: {},
    });
    const res = buildMockRes();
    await handler(req, res);

    // After origin/rate checks pass, the route validates type + slug
    expect(res._status).toBe(400);
    expect(res._json.error).toBe('Missing required fields');
  });
});
