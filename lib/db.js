'use strict';
const initSqlJs = require('sql.js');

let _db    = null;
let _ready = false;

function dbAll(db, sql, params) {
  const stmt = db.prepare(sql);
  if (params && params.length) stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function dbGet(db, sql, params) {
  return dbAll(db, sql, params)[0] || null;
}

function dbRun(db, sql, params) {
  if (params && params.length) {
    const stmt = db.prepare(sql);
    stmt.run(params);
    stmt.free();
  } else {
    db.run(sql);
  }
}

async function getDb() {
  if (_db && _ready) return _db;

  const SQL = await initSqlJs();
  const db  = new SQL.Database();

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      username     TEXT UNIQUE NOT NULL,
      password     TEXT NOT NULL,
      role         TEXT DEFAULT 'viewer',
      bio          TEXT DEFAULT '',
      created_at   TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS boards (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      title        TEXT NOT NULL,
      content      TEXT NOT NULL,
      owner_id     INTEGER NOT NULL,
      visibility   TEXT DEFAULT 'private',
      created_at   TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS system_config (
      key          TEXT PRIMARY KEY,
      value        TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER,
      action       TEXT,
      detail       TEXT,
      ts           TEXT DEFAULT (datetime('now'))
    );
  `);

  // Passwords stored in PLAINTEXT — intentional for CTF SQLi challenge
  // Player discovers these via UNION-based injection
  dbRun(db, "INSERT OR IGNORE INTO users (username,password,role) VALUES (?,?,?)", ['nexusadmin', 'Nx@dm1n_S3cur3!', 'admin']);
  dbRun(db, "INSERT OR IGNORE INTO users (username,password,role) VALUES (?,?,?)", ['alice',      'member1234',     'member']);
  dbRun(db, "INSERT OR IGNORE INTO users (username,password,role) VALUES (?,?,?)", ['bob',        'bob_viewer_99',  'viewer']);

  dbRun(db, "INSERT OR IGNORE INTO boards (id,title,content,owner_id,visibility) VALUES (?,?,?,?,?)",
    [1, 'Admin Notes', 'Internal board. Flag is stored in system_config under key: master_flag', 1, 'private']);
  dbRun(db, "INSERT OR IGNORE INTO boards (id,title,content,owner_id,visibility) VALUES (?,?,?,?,?)",
    [2, 'Welcome Board', 'Welcome to NexusBoard! Public board for all members.', 2, 'public']);

  dbRun(db, "INSERT OR REPLACE INTO system_config (key,value) VALUES (?,?)", ['master_flag',      'softwarica{ch41ned_vuln3r4b1l1ty_m4st3r_0f_n3xus_b04rd}']);
  dbRun(db, "INSERT OR REPLACE INTO system_config (key,value) VALUES (?,?)", ['site_name',        'NexusBoard v2.1']);
  dbRun(db, "INSERT OR REPLACE INTO system_config (key,value) VALUES (?,?)", ['maintenance_mode', 'false']);
  dbRun(db, "INSERT OR REPLACE INTO system_config (key,value) VALUES (?,?)", ['smtp_host',        'mail.nexus.internal']);
  dbRun(db, "INSERT OR REPLACE INTO system_config (key,value) VALUES (?,?)", ['backup_path',      '/var/nexus/backups']);

  _db    = db;
  _ready = true;
  console.log('[nexus] DB ready');
  return db;
}

module.exports = { getDb, dbAll, dbGet, dbRun };