'use strict';
/**
 * Lightweight cookie-based session for Vercel serverless.
 * Signs a JSON payload with HMAC-SHA256 → stored in a single cookie.
 * No server-side state needed — works across cold starts.
 */
const crypto = require('crypto');

const COOKIE_NAME   = 'nx_sess';
const SESSION_SECRET = process.env.SESSION_SECRET || 'nexus_cookie_secret_v2_internal';
const MAX_AGE_SEC   = 3600; // 1 hour

function sign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verify(token) {
  try {
    const [data, sig] = token.split('.');
    if (!data || !sig) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    return JSON.parse(Buffer.from(data, 'base64url').toString());
  } catch { return null; }
}

/** Middleware: reads cookie → req.sess */
function sessionMiddleware(req, res, next) {
  const raw  = req.cookies?.[COOKIE_NAME];
  req.sess   = raw ? (verify(raw) || {}) : {};

  req.sess.save = function () {
    const token = sign(req.sess);
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      maxAge:   MAX_AGE_SEC * 1000,
      sameSite: 'lax',
      // secure: true on Vercel (HTTPS only) — omit for local dev
      ...(process.env.VERCEL ? { secure: true } : {})
    });
  };

  req.sess.destroy = function () {
    res.clearCookie(COOKIE_NAME);
    req.sess = {};
  };

  next();
}

module.exports = { sessionMiddleware };
