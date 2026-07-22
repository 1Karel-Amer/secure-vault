/**
 * Pure-JS JSON file database — no native modules, no compilation needed.
 * All data is stored in data/vault.json and auto-saved every 5 seconds.
 */
const fs   = require('fs');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../data/vault.json');

// In-memory store
let store = {
  honeypot_logs:   [],
  auth_logs:       [],
  banned_ips:      {}, // keyed by IP for O(1) lookup
  active_sessions: [],
};

let _nextId = { honeypot: 1, auth: 1, session: 1 };

// ── Init ──────────────────────────────────────────────────────────────────────
function initDatabase() {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  if (fs.existsSync(DB_PATH)) {
    try {
      const loaded = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
      store.honeypot_logs   = loaded.honeypot_logs   || [];
      store.auth_logs       = loaded.auth_logs       || [];
      store.banned_ips      = loaded.banned_ips      || {};
      store.active_sessions = loaded.active_sessions || [];
    } catch (e) {
      console.error('[DB] Could not parse existing DB, starting fresh:', e.message);
    }
  }

  console.log('[DB] JSON database ready at', DB_PATH);
}

function _save() {
  try {
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(store, null, 2), 'utf8');
  } catch (e) {
    console.error('[DB] Save error:', e.message);
  }
}

// Auto-save every 5 seconds + on process exit
setInterval(_save, 5000).unref();
process.on('exit',   _save);
process.on('SIGINT',  () => { _save(); process.exit(0); });
process.on('SIGTERM', () => { _save(); process.exit(0); });

function _now() { return new Date().toISOString(); }

// ── Honeypot Logs ─────────────────────────────────────────────────────────────
function logHoneypot(ip, usernameTried, userAgent, eventType = 'attempt') {
  store.honeypot_logs.unshift({
    id: _nextId.honeypot++,
    ip,
    username_tried: usernameTried || '',
    user_agent:     userAgent     || '',
    event_type:     eventType,
    timestamp:      _now(),
  });
  if (store.honeypot_logs.length > 500) store.honeypot_logs.length = 500;
}

function getHoneypotLogs(limit = 200) {
  return store.honeypot_logs.slice(0, limit);
}

// ── Auth Logs ─────────────────────────────────────────────────────────────────
function logAuth(ip, username, stage, success, userAgent) {
  store.auth_logs.unshift({
    id:        _nextId.auth++,
    ip,
    username:  username  || 'unknown',
    stage,
    success:   success ? 1 : 0,
    user_agent: userAgent || '',
    timestamp:  _now(),
  });
  if (store.auth_logs.length > 500) store.auth_logs.length = 500;
}

function getAuthLogs(limit = 200) {
  return store.auth_logs.slice(0, limit);
}

// ── Banned IPs ────────────────────────────────────────────────────────────────
function banIp(ip, durationMs, reason) {
  const existing = store.banned_ips[ip];
  store.banned_ips[ip] = {
    ip,
    banned_until: new Date(Date.now() + durationMs).toISOString(),
    reason:       reason || 'Unknown',
    hit_count:    existing ? existing.hit_count + 1 : 1,
  };
}

function isBanned(ip) {
  const ban = store.banned_ips[ip];
  if (!ban) return false;
  if (new Date(ban.banned_until) > new Date()) return true;
  delete store.banned_ips[ip]; // expired, clean up
  return false;
}

function getBannedIps() {
  return Object.values(store.banned_ips)
    .filter(b => new Date(b.banned_until) > new Date())
    .sort((a, b) => b.hit_count - a.hit_count);
}

// ── Sessions ──────────────────────────────────────────────────────────────────
function addSession(username, ip, fingerprint, expiresAt) {
  store.active_sessions.unshift({
    id:         _nextId.session++,
    username,
    ip,
    fingerprint,
    created_at: _now(),
    expires_at: expiresAt,
  });
  // Prune expired sessions automatically
  store.active_sessions = store.active_sessions.filter(
    s => new Date(s.expires_at) > new Date()
  );
}

function getActiveSessions() {
  return store.active_sessions.filter(s => new Date(s.expires_at) > new Date());
}

// ── Stats ─────────────────────────────────────────────────────────────────────
function getStats() {
  return {
    honeypotHits: store.honeypot_logs.filter(l => l.event_type === 'attempt').length,
    bannedCount:  getBannedIps().length,
    authFails:    store.auth_logs.filter(l => l.success === 0).length,
    authSuccess:  store.auth_logs.filter(l => l.success === 1 && l.stage === 'totp').length,
  };
}

module.exports = {
  initDatabase,
  logHoneypot,
  getHoneypotLogs,
  logAuth,
  getAuthLogs,
  banIp,
  isBanned,
  getBannedIps,
  addSession,
  getActiveSessions,
  getStats,
};
