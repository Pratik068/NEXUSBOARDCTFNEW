'use strict';

const express      = require('express');
const cookieParser = require('cookie-parser');
const morgan       = require('morgan');
const jwt          = require('jsonwebtoken');
const bcrypt       = require('bcryptjs');
const ejs          = require('ejs');
const fetch        = require('node-fetch');
const path         = require('path');
const fs           = require('fs');

const { getDb, dbAll, dbGet, dbRun } = require('../lib/db');
const { sessionMiddleware }          = require('../lib/session');

const app = express();

// ── JWT algorithm-confusion "public key" (exposed at /api/pubkey) ────────────
const FAKE_PUBKEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgksPkgG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xHn/ygWe
p4nxTnKDSMRsEVFMbFmcCLb3CRoMQT5NXQM8z5WjFr3Sn0b9mKgJxW6rYL8Gvd0
Af3p1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B9C0D1
E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6T7U8V9W0X1Y2Z3a4b5c6d7e8f9g0h1i2j3k4
l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9AQAB
-----END PUBLIC KEY-----`;

// ── Static CSS served inline (Vercel can't serve /public via express.static) ─
const CSS_FILE = path.join(__dirname, '..', 'public', 'css', 'style.css');

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(sessionMiddleware);

// Serve CSS
app.get('/public/css/style.css', (req, res) => {
  res.setHeader('Content-Type', 'text/css');
  res.sendFile(CSS_FILE);
});

// ── EJS helper ─────────────────────────────────────────────────────────────────
const VIEWS = path.join(__dirname, '..', 'views');
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

// ── Auth guards ───────────────────────────────────────────────────────────────
function requireLogin(req, res, next) {
  if (req.sess?.userId) return next();
  res.redirect('/login');
}
function requireAdmin(req, res, next) {
  if (req.sess?.role === 'admin') return next();
  res.status(403); renderView(res, 'error', { message: 'Access denied.' });
}

// ═════════════════════════════════════════════════════════════════════════════
// PUBLIC ROUTES
// ═════════════════════════════════════════════════════════════════════════════

app.get('/', (req, res) => renderView(res, 'index', { user: req.sess?.username || null }));

// ──────────────────────────────────────────────────────────────────────────────
//  VULN 1 — SQL INJECTION  (login, username field, UNION-based)
//  Raw interpolation: SELECT * FROM users WHERE username = '${username}'
// ──────────────────────────────────────────────────────────────────────────────
app.get('/login', (req, res) => renderView(res, 'login', { error: null }));
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const db = await getDb();
  try {
    // VULNERABLE — string interpolated directly into SQL, no parameterization
    const user = dbGet(db, `SELECT * FROM users WHERE username = '${username}'`);
    if (!user) return renderView(res, 'login', { error: 'Invalid credentials.' });
    if (!bcrypt.compareSync(String(password), String(user.password)))
      return renderView(res, 'login', { error: 'Invalid credentials.' });

    req.sess.userId   = user.id;
    req.sess.username = user.username;
    req.sess.role     = user.role;
    req.sess.save();

    dbRun(db, `INSERT INTO audit_log (user_id,action,detail) VALUES (${user.id},'login','web session')`);
    res.redirect('/dashboard');
  } catch (e) {
    renderView(res, 'login', { error: 'An error occurred.' });
  }
});

app.get('/logout', (req, res) => { req.sess.destroy(); res.redirect('/'); });

app.get('/register', (req, res) => renderView(res, 'register', { error: null }));
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 3 || password.length < 6)
    return renderView(res, 'register', { error: 'Username ≥3 chars, password ≥6 chars.' });
  const db = await getDb();
  try {
    dbRun(db, 'INSERT INTO users (username,password,role) VALUES (?,?,?)',
      [username, bcrypt.hashSync(password, 10), 'viewer']);
    res.redirect('/login');
  } catch (e) {
    renderView(res, 'register', { error: 'Username already taken.' });
  }
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/dashboard', requireLogin, async (req, res) => {
  const db = await getDb();
  const boards = dbAll(db,
    `SELECT b.id, b.title, b.visibility, b.created_at, u.username AS owner
     FROM boards b JOIN users u ON b.owner_id = u.id
     WHERE b.visibility = 'public' OR b.owner_id = ?`,
    [req.sess.userId]
  );
  renderView(res, 'dashboard', { user: req.sess.username, role: req.sess.role, boards });
});

// ──────────────────────────────────────────────────────────────────────────────
//  VULN 2 — IDOR  (board/:id — no ownership or visibility enforcement)
// ──────────────────────────────────────────────────────────────────────────────
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
  const db = await getDb();
  // VULNERABLE — any authenticated user can access any board by guessing the id
  const board = dbGet(db,
    'SELECT b.*, u.username AS owner FROM boards b JOIN users u ON b.owner_id = u.id WHERE b.id = ?',
    [parseInt(req.params.id)]
  );
  if (!board) { res.status(404); return renderView(res, 'error', { message: 'Board not found.' }); }
  renderView(res, 'board', { user: req.sess.username, role: req.sess.role, board });
});

// ──────────────────────────────────────────────────────────────────────────────
//  VULN 3 — SSTI  (profile bio rendered as EJS with dangerous locals)
//  Locals passed to ejs.render: require, process, db, dbGet, dbAll
// ──────────────────────────────────────────────────────────────────────────────
app.get('/profile', requireLogin, async (req, res) => {
  const db   = await getDb();
  const user = dbGet(db, 'SELECT * FROM users WHERE id = ?', [req.sess.userId]);
  renderView(res, 'profile', { user: req.sess.username, role: req.sess.role, bio: user.bio || '' });
});

app.post('/profile', requireLogin, async (req, res) => {
  const db = await getDb();
  dbRun(db, 'UPDATE users SET bio = ? WHERE id = ?', [req.body.bio || '', req.sess.userId]);
  res.redirect('/profile/view/' + req.sess.userId);
});

app.get('/profile/view/:id', requireLogin, async (req, res) => {
  const db         = await getDb();
  const targetUser = dbGet(db, 'SELECT * FROM users WHERE id = ?', [parseInt(req.params.id)]);
  if (!targetUser) { res.status(404); return renderView(res, 'error', { message: 'User not found.' }); }

  let rendered = '';
  try {
    // VULNERABLE — bio compiled and executed as an EJS template
    // process, require, db, dbGet, dbAll are all in scope — full RCE / data access
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

// ──────────────────────────────────────────────────────────────────────────────
//  VULN 4 — JWT ALGORITHM CONFUSION
//  Server signs/verifies with HS256 using FAKE_PUBKEY as secret.
//  FAKE_PUBKEY is exposed at /api/pubkey → attacker forges admin token.
// ──────────────────────────────────────────────────────────────────────────────
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
  if (!token) { res.status(401); return renderView(res, 'error', { message: 'Token required. Supply via X-Nexus-Token header.' }); }
  try {
    // VULNERABLE — HS256 accepted alongside RS256; pubkey is the HS256 secret → forgeable
    const decoded = jwt.verify(token, FAKE_PUBKEY, { algorithms: ['HS256', 'RS256'] });
    if (decoded.role !== 'admin') { res.status(403); return renderView(res, 'error', { message: 'Insufficient privileges.' }); }
    const db     = await getDb();
    const users  = dbAll(db, 'SELECT id, username, role, bio, created_at FROM users');
    const config = dbAll(db, 'SELECT * FROM system_config');
    const logs   = dbAll(db, 'SELECT * FROM audit_log ORDER BY ts DESC LIMIT 50');
    renderView(res, 'admin', { decoded, users, config, logs });
  } catch (e) {
    res.status(401); renderView(res, 'error', { message: 'Invalid or expired token.' });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
//  VULN 5 — SSRF  (webhook tester; accepts file:// → reads local filesystem)
//  Members+ only. No URL validation whatsoever.
// ──────────────────────────────────────────────────────────────────────────────
app.get('/webhooks', requireLogin, (req, res) => {
  if (req.sess.role === 'viewer') {
    res.status(403); return renderView(res, 'error', { message: 'Members only. Upgrade your account.' });
  }
  renderView(res, 'webhooks', { user: req.sess.username, result: null, error: null });
});

app.post('/webhooks/test', requireLogin, async (req, res) => {
  if (req.sess.role === 'viewer') {
    res.status(403); return renderView(res, 'error', { message: 'Access denied.' });
  }
  const { url } = req.body;
  if (!url) return renderView(res, 'webhooks', { user: req.sess.username, result: null, error: 'URL required.' });

  try {
    let result;
    if (url.startsWith('file://')) {
      // VULNERABLE — arbitrary local file read via file:// protocol
      result = fs.readFileSync(url.slice(7), 'utf8');
    } else {
      const r = await fetch(url, { timeout: 6000 });
      result  = await r.text();
    }
    const out = result.length > 5000 ? result.slice(0, 5000) + '\n...[truncated]' : result;
    renderView(res, 'webhooks', { user: req.sess.username, result: out, error: null });
  } catch (e) {
    renderView(res, 'webhooks', { user: req.sess.username, result: null, error: 'Webhook request failed.' });
  }
});

// ── Red herrings & utility ────────────────────────────────────────────────────
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
  res.status(404); renderView(res, 'error', { message: 'Not found.' });
});

// ── Local dev boot (ignored by Vercel) ───────────────────────────────────────
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  getDb().then(() =>
    app.listen(PORT, () => console.log(`NexusBoard running on http://localhost:${PORT}`))
  ).catch(e => { console.error(e); process.exit(1); });
}

module.exports = app;
