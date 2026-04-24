/**
 * Origin validation and per-IP rate limiting for vendor-credential API routes.
 *
 * Routes that proxy server-held secrets (OpenAI, Gmail SMTP) must gate access
 * to prevent external sites or bots from draining paid vendor quotas.
 *
 * Follows the GOOGLE_WALLET_ALLOWED_ORIGINS pattern already used in
 * api/google-wallet-pass.js — reads a comma-separated allowlist from an env var
 * and validates the incoming Origin (or Referer) header against it.
 *
 * Rate limiting uses an in-memory sliding window per IP. This is best-effort
 * per serverless instance; cross-instance durability would require a shared
 * store like Supabase or Redis, which is out of scope for this change.
 */

const DEFAULT_ORIGINS = "https://hushhtech.com,https://www.hushhtech.com";

function parseAllowedOrigins() {
  return (process.env.API_ALLOWED_ORIGINS || DEFAULT_ORIGINS)
    .split(",")
    .map((origin) => origin.trim().replace(/\/+$/, ""))
    .filter(Boolean);
}

function extractRequestOrigin(req) {
  const origin = (req.headers?.origin || "").trim();
  if (origin) return origin;

  // Some clients omit Origin but include Referer — extract the origin portion
  const referer = (req.headers?.referer || "").trim();
  if (!referer) return "";

  try {
    const parsed = new URL(referer);
    return parsed.origin;
  } catch {
    return "";
  }
}

/**
 * Validates the request origin against the configured allowlist.
 * In non-production environments, all origins are permitted so local
 * development and testing are not blocked.
 *
 * @returns {boolean} true if the request was blocked (response already sent)
 */
export function validateRequestOrigin(req, res) {
  if (process.env.NODE_ENV !== "production") {
    return false;
  }

  const requestOrigin = extractRequestOrigin(req);
  const allowedOrigins = parseAllowedOrigins();

  if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
    res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Vary", "Origin");
    return false;
  }

  res.status(403).json({
    error: "Forbidden",
    code: "ORIGIN_NOT_ALLOWED",
  });
  return true;
}

// ---------------------------------------------------------------------------
// Per-IP in-memory rate limiter
// ---------------------------------------------------------------------------

const ipRequestLog = new Map();

// Prevent unbounded memory growth: drop entries older than twice the window
function pruneStaleEntries(windowMs) {
  const cutoff = Date.now() - windowMs * 2;
  for (const [ip, timestamps] of ipRequestLog.entries()) {
    const recent = timestamps.filter((ts) => ts > cutoff);
    if (recent.length === 0) {
      ipRequestLog.delete(ip);
    } else {
      ipRequestLog.set(ip, recent);
    }
  }
}

function getClientIp(req) {
  // Vercel and Cloud Run set x-forwarded-for; fall back to socket address
  const forwarded = req.headers?.["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

/**
 * Enforces a per-IP request rate limit using a sliding window.
 *
 * @param {object}  req
 * @param {object}  res
 * @param {object}  options
 * @param {number}  options.windowMs    - Window size in milliseconds (default 60 000)
 * @param {number}  options.maxRequests - Max requests per window (default 20)
 * @returns {boolean} true if the request was blocked (response already sent)
 */
export function checkRequestRateLimit(
  req,
  res,
  { windowMs = 60_000, maxRequests = 20 } = {}
) {
  pruneStaleEntries(windowMs);

  const clientIp = getClientIp(req);
  const now = Date.now();
  const windowStart = now - windowMs;

  const timestamps = ipRequestLog.get(clientIp) || [];
  const recentRequests = timestamps.filter((ts) => ts > windowStart);

  if (recentRequests.length >= maxRequests) {
    const retryAfterSeconds = Math.ceil(windowMs / 1000);
    res.setHeader("Retry-After", String(retryAfterSeconds));
    res.status(429).json({
      error: "Too many requests",
      code: "RATE_LIMIT_EXCEEDED",
      retryAfterSeconds,
    });
    return true;
  }

  recentRequests.push(now);
  ipRequestLog.set(clientIp, recentRequests);
  return false;
}

// Exported for tests only
export function __resetRateLimitState() {
  ipRequestLog.clear();
}
