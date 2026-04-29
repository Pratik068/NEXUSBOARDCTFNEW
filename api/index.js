'use strict';

const express      = require('express');
const cookieParser = require('cookie-parser');
const morgan       = require('morgan');
const jwt          = require('jsonwebtoken');
const ejs          = require('ejs');
const fetch        = require('node-fetch');
const path         = require('path');
const fs           = require('fs');

const { getDb, dbAll, dbGet, dbRun } = require('../lib/db');
const { sessionMiddleware }          = require('../lib/session');

const app = express();

const FAKE_PUBKEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgksPkgG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xHn/ygWe
p4nxTnKDSMRsEVFMbFmcCLb3CRoMQT5NXQM8z5WjFr3Sn0b9mKgJxW6rYL8Gvd0
Af3p1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B9C0D1
E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6T7U8V9W0X1Y2Z3a4b5c6d7e8f9g0h1i2j3k4
l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9AQAB
-----END PUBLIC KEY-----`;

const CSS_FILE = path.join(__dirname, '..', 'public', 'css', 'style.css');
const VIEWS    = path.join(__dirname, '..', 'views');

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(sessionMiddleware);

app.get('/public/css/style.css', (req, res) => {
  res.setHeader('Content-Type', 'text/css');
  res.sendFile(CSS_FILE);
});

// ── EJS renderer ──────────────────────────────────────────────────────────────
function renderView(res, name, locals = {}) {
  try {
    const file = path.join(VIEWS, name + '.ejs');
    const html = ejs.render(fs.readFileSync(file, 'utf8'), locals, { filename: file });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(html);
  } catch (e) {
    console.error('renderView error:', e);
    res.status(500).end('Render error');
  }
}

// ── Auth guards ────────────────────────────────────────────────────────────────
function requireLogin(req, res, next) {
  if (req.sess?.userId) return next();
  res.redirect('/login');
}
function requireAdmin(req, res, next) {
  if (req.sess?.role === 'admin') return next();
  res.status(403);
  renderView(res, 'error', { message: 'Access denied.' });
}

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────────────────────────

app.get('/', (req, res) =>
  renderView(res, 'index', { user: req.sess?.username || null }));

// ─────────────────────────────────────────────────────────────────────────────
//  VULN 1 — SQL INJECTION (username field on /login)
//
//  Detection chain:
//    '          → prepare() throws syntax error → HTTP 500, raw error shown
//    ' ORDER BY 6--  → 0 rows, no error (valid, 6 cols exist)
//    ' ORDER BY 7--  → prepare() throws "out of range" → HTTP 500
//    ' UNION SELECT tbl_name,2,3,4,5,6 FROM sqlite_master WHERE type='table'-- 
//               → rows returned, ALL reflected in yellow box
//    ' UNION SELECT sql,2,3,4,5,6 FROM sqlite_master WHERE type='table' AND tbl_name='users'--
//               → CREATE TABLE DDL reflected, reveals column names
//    ' UNION SELECT username,password,3,4,5,6 FROM users--
//               → credentials reflected, nexusadmin:Nx@dm1n_S3cur3! visible
//
//  Key design:
//    - prepare() throws on bad SQL → caught, HTTP 500 + raw message shown
//    - Valid injections return rows; we detect "injected" rows by checking
//      whether id is a real INTEGER (typeof === 'number') vs a string value
//      smuggled in from a UNION.  If ANY row has a non-integer id, we treat
//      the whole result as an injection dump and reflect all rows.
//    - Normal login: id is always a real integer → password check proceeds.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/login', (req, res) =>
  renderView(res, 'login', { loginErr: null, sqlError: null }));

app.post('/login', async (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const db = await getDb();

  // ── Step 1: execute the vulnerable query ──────────────────────────────────
  let rows;
  try {
    // VULNERABLE: raw string interpolation — no sanitisation whatsoever
    rows = dbAll(db, `SELECT * FROM users WHERE username = '${username}'`);
  } catch (sqlErr) {
    // prepare() threw — bad SQL syntax (single quote, ORDER BY out of range, etc.)
    // Reflect the raw error message so the player knows injection is possible
    res.status(500);
    return renderView(res, 'login', {
      loginErr : null,
      sqlError : `SQL Error: ${sqlErr.message}`
    });
  }

  // ── Step 2: detect whether this is a UNION injection ─────────────────────
  // Real rows from the users table always have a numeric integer id.
  // UNION-injected rows put arbitrary values in the id column (strings, etc.).
  // We also reflect if more rows come back than could ever match one username.
  const isInjected = rows.some(r => typeof r.id !== 'number') || rows.length > 1;

  if (isInjected) {
    // Reflect everything — this is what lets the player read dumped data
    const lines = rows.map(r => Object.values(r).join('  |  ')).join('\n');
    return renderView(res, 'login', {
      loginErr : null,
      sqlError : `Query returned ${rows.length} row(s):\n${lines}`
    });
  }

  // ── Step 3: normal auth flow ──────────────────────────────────────────────
  if (!rows || rows.length === 0) {
    return renderView(res, 'login', {
      loginErr : 'Invalid credentials.',
      sqlError : null
    });
  }

  const user = rows[0];

  // Plaintext comparison — passwords are stored in plaintext in this CTF
  if (String(user.password) !== String(password)) {
    return renderView(res, 'login', {
      loginErr : 'Invalid credentials.',
      sqlError : null
    });
  }

  // ── Step 4: authenticated ─────────────────────────────────────────────────
  req.sess.userId   = user.id;
  req.sess.username = user.username;
  req.sess.role     = user.role;
  req.sess.save();

  try {
    dbRun(db, `INSERT INTO audit_log (user_id,action,detail) VALUES (${user.id},'login','web session')`);
  } catch (_) { /* non-critical */ }

  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => { req.sess.destroy(); res.redirect('/'); });

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard
// ─────────────────────────────────────────────────────────────────────────────
app.get('/dashboard', requireLogin, async (req, res) => {
  const db     = await getDb();
  const boards = dbAll(db,
    `SELECT b.id, b.title, b.visibility, b.created_at, u.username AS owner
     FROM boards b JOIN users u ON b.owner_id = u.id
     WHERE b.visibility = 'public' OR b.owner_id = ?`,
    [req.sess.userId]
  );
  renderView(res, 'dashboard', { user: req.sess.username, role: req.sess.role, boards });
});

// ─────────────────────────────────────────────────────────────────────────────
//  VULN 2 — IDOR (/board/:id — no ownership or visibility check)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/board/new', requireLogin, (req, res) =>
  renderView(res, 'new_board', { user: req.sess.username }));

app.post('/board/new', requireLogin, async (req, res) => {
  const { title, content, visibility } = req.body;
  const vis = ['public', 'private'].includes(visibility) ? visibility : 'private';
  const db  = await getDb();
  dbRun(db, 'INSERT INTO boards (title,content,owner_id,visibility) VALUES (?,?,?,?)',
    [title, content, req.sess.userId, vis]);
  res.redirect('/dashboard');
});

app.get('/board/:id', requireLogin, async (req, res) => {
  const db    = await getDb();
  // VULNERABLE — no visibility or ownership check on the id parameter
  const board = dbGet(db,
    'SELECT b.*, u.username AS owner FROM boards b JOIN users u ON b.owner_id = u.id WHERE b.id = ?',
    [parseInt(req.params.id)]
  );
  if (!board) {
    res.status(404);
    return renderView(res, 'error', { message: 'Board not found.' });
  }
  renderView(res, 'board', { user: req.sess.username, role: req.sess.role, board });
});

// ─────────────────────────────────────────────────────────────────────────────
//  VULN 3 — SSTI (profile bio rendered as live EJS with dangerous locals)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/profile', requireLogin, async (req, res) => {
  const db   = await getDb();
  const user = dbGet(db, 'SELECT * FROM users WHERE id = ?', [req.sess.userId]);
  renderView(res, 'profile', {
    user : req.sess.username,
    role : req.sess.role,
    bio  : user.bio || ''
  });
});

app.post('/profile', requireLogin, async (req, res) => {
  const db = await getDb();
  dbRun(db, 'UPDATE users SET bio = ? WHERE id = ?', [req.body.bio || '', req.sess.userId]);
  res.redirect('/profile/view/' + req.sess.userId);
});

app.get('/profile/view/:id', requireLogin, async (req, res) => {
  const db         = await getDb();
  const targetUser = dbGet(db, 'SELECT * FROM users WHERE id = ?', [parseInt(req.params.id)]);
  if (!targetUser) {
    res.status(404);
    return renderView(res, 'error', { message: 'User not found.' });
  }

  let rendered = '';
  try {
    // VULNERABLE — bio executed as EJS; process/require/db/dbAll in scope
    rendered = ejs.render(String(targetUser.bio || ''), {
      username : targetUser.username,
      role     : targetUser.role,
      process  : process,
      require  : require,
      db       : db,
      dbGet    : (sql, p) => dbGet(db, sql, p),
      dbAll    : (sql, p) => dbAll(db, sql, p),
    });
  } catch (e) {
    rendered = '[Bio rendering error]';
  }

  renderView(res, 'profile_view', {
    user           : req.sess.username,
    role           : req.sess.role,
    targetUsername : targetUser.username,
    targetRole     : targetUser.role,
    renderedBio    : rendered,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  VULN 4 — JWT ALGORITHM CONFUSION
//  /api/pubkey leaks the key used as the HS256 secret → forgeable admin tokens
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/pubkey', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.end(FAKE_PUBKEY);
});

app.get('/api/admin/token', requireLogin, requireAdmin, (req, res) => {
  const token = jwt.sign(
    { userId: req.sess.userId, username: req.sess.username, role: 'admin' },
    FAKE_PUBKEY,
    { algorithm: 'HS256', expiresIn: '2h' }
  );
  res.json({ token });
});

app.get('/admin', async (req, res) => {
  const token = req.headers['x-nexus-token'] || req.query.token;
  if (!token) {
    res.status(401);
    return renderView(res, 'error', { message: 'Token required. Supply via X-Nexus-Token header.' });
  }
  try {
    // VULNERABLE — accepts HS256; pubkey is the HS256 secret → attacker can forge
    const decoded = jwt.verify(token, FAKE_PUBKEY, { algorithms: ['HS256', 'RS256'] });
    if (decoded.role !== 'admin') {
      res.status(403);
      return renderView(res, 'error', { message: 'Insufficient privileges.' });
    }
    const db     = await getDb();
    const users  = dbAll(db, 'SELECT id, username, role, bio, created_at FROM users');
    const config = dbAll(db, 'SELECT * FROM system_config');
    const logs   = dbAll(db, 'SELECT * FROM audit_log ORDER BY ts DESC LIMIT 50');
    renderView(res, 'admin', { decoded, users, config, logs });
  } catch (e) {
    res.status(401);
    renderView(res, 'error', { message: 'Invalid or expired token.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  VULN 5 — SSRF (webhook tester; file:// reads arbitrary local files)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/webhooks', requireLogin, (req, res) => {
  if (req.sess.role === 'viewer') {
    res.status(403);
    return renderView(res, 'error', { message: 'Members only. Upgrade your account.' });
  }
  renderView(res, 'webhooks', { user: req.sess.username, result: null, error: null });
});

app.post('/webhooks/test', requireLogin, async (req, res) => {
  if (req.sess.role === 'viewer') {
    res.status(403);
    return renderView(res, 'error', { message: 'Access denied.' });
  }
  const { url } = req.body;
  if (!url) {
    return renderView(res, 'webhooks', {
      user: req.sess.username, result: null, error: 'URL required.'
    });
  }

  try {
    let result;
    if (url.startsWith('file://')) {
      // VULNERABLE — no protocol blocklist; reads arbitrary local files
      result = fs.readFileSync(url.slice(7), 'utf8');
    } else {
      const r = await fetch(url, { timeout: 6000 });
      result  = await r.text();
    }
    const out = result.length > 5000
      ? result.slice(0, 5000) + '\n...[truncated]'
      : result;
    renderView(res, 'webhooks', { user: req.sess.username, result: out, error: null });
  } catch (e) {
    renderView(res, 'webhooks', {
      user: req.sess.username, result: null, error: 'Webhook request failed.'
    });
  }
});

// ── Red herrings ───────────────────────────────────────────────────────────────
app.get('/api/status', (req, res) =>
  res.json({ status: 'ok', version: '2.1.0', uptime: process.uptime() }));

app.get('/api/boards/public', async (req, res) => {
  const db = await getDb();
  res.json(dbAll(db, "SELECT id, title, owner_id, created_at FROM boards WHERE visibility = 'public'"));
});

app.get('/api/flag', requireLogin, (req, res) =>
  res.json({ message: 'The flag is not here.' }));

app.get('/admin/export', requireLogin, requireAdmin, (req, res) =>
  res.json({ note: 'Feature coming soon.' }));

// 404
app.use((req, res) => {
  res.status(404);
  renderView(res, 'error', { message: 'Not found.' });
});

// ── Local dev boot (Vercel ignores this) ──────────────────────────────────────
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  getDb().then(() =>
    app.listen(PORT, () => console.log(`NexusBoard running on http://localhost:${PORT}`))
  ).catch(e => { console.error(e); process.exit(1); });
}

module.exports = app;