const express   = require('express');
const router    = express.Router();
const jwt       = require('jsonwebtoken');
const path      = require('path');
const db        = require('../db/database');
const { verifyPassphrase, verifyPassword } = require('../utils/crypto');
const { verifyTOTP }        = require('../utils/totp');
const { createFingerprint } = require('../middleware/fingerprint');
const { authLimiter }       = require('../middleware/rateLimit');

const STEP_SECRET  = process.env.STEP_TOKEN_SECRET || 'fallback-step-secret';
const JWT_SECRET   = process.env.JWT_SECRET        || 'fallback-jwt-secret';
const SESSION_SECS = 30 * 60; // 30 minutes

// ── Block banned IPs before any auth ──
router.use((req, res, next) => {
  if (db.isBanned(req.ip)) {
    console.log(`[AUTH] Banned IP attempted access: ${req.ip}`);
    return res.status(403).json({ error: 'Access denied.' });
  }
  next();
});

// ── GET / — Serve the real (hidden) login page ──
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../views/auth.html'));
});

// ════════════════════════════════════════
//  STEP 1 — Group Passphrase
// ════════════════════════════════════════
router.post('/step1', authLimiter, async (req, res) => {
  const { passphrase } = req.body;
  const ua = req.get('User-Agent') || '';

  if (!passphrase || typeof passphrase !== 'string') {
    return res.status(400).json({ error: 'Missing passphrase.' });
  }

  const valid = await verifyPassphrase(passphrase.trim());
  db.logAuth(req.ip, null, 'passphrase', valid, ua);

  if (!valid) {
    await new Promise(r => setTimeout(r, 1500 + Math.random() * 500));
    return res.status(401).json({ error: 'Incorrect passphrase.' });
  }

  const step1Token = jwt.sign({ step: 1 }, STEP_SECRET, { expiresIn: '5m' });
  res.json({ token: step1Token });
});

// ════════════════════════════════════════
//  STEP 2 — Username + Password
// ════════════════════════════════════════
router.post('/step2', authLimiter, async (req, res) => {
  const { username, password, step1Token } = req.body;
  const ua = req.get('User-Agent') || '';

  if (!username || !password || !step1Token) {
    return res.status(400).json({ error: 'Missing credentials.' });
  }

  try {
    const decoded = jwt.verify(step1Token, STEP_SECRET);
    if (decoded.step !== 1) throw new Error('Wrong step');
  } catch {
    return res.status(401).json({ error: 'Session expired. Start over.' });
  }

  const valid = await verifyPassword(username.trim(), password);
  db.logAuth(req.ip, username.trim(), 'credentials', valid, ua);

  if (!valid) {
    await new Promise(r => setTimeout(r, 1500 + Math.random() * 500));
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const step2Token = jwt.sign(
    { step: 2, username: username.trim().toLowerCase() },
    STEP_SECRET,
    { expiresIn: '5m' }
  );
  res.json({ token: step2Token });
});

// ════════════════════════════════════════
//  STEP 3 — TOTP (Google Authenticator)
// ════════════════════════════════════════
router.post('/step3', authLimiter, async (req, res) => {
  const { totpCode, step2Token } = req.body;
  const ua = req.get('User-Agent') || '';

  if (!totpCode || !step2Token) {
    return res.status(400).json({ error: 'Missing TOTP code.' });
  }

  let username;
  try {
    const decoded = jwt.verify(step2Token, STEP_SECRET);
    if (decoded.step !== 2) throw new Error('Wrong step');
    username = decoded.username;
  } catch {
    return res.status(401).json({ error: 'Session expired. Start over.' });
  }

  const valid = verifyTOTP(username, totpCode);
  db.logAuth(req.ip, username, 'totp', valid, ua);

  if (!valid) {
    return res.status(401).json({ error: 'Invalid or expired TOTP code.' });
  }

  // ── All 3 factors verified — issue final session JWT ──
  const fingerprint = createFingerprint(req);
  const sessionToken = jwt.sign(
    { username, fingerprint, type: 'session' },
    JWT_SECRET,
    { expiresIn: '30m' }
  );

  const expiresAt = new Date(Date.now() + SESSION_SECS * 1000).toISOString();
  db.addSession(username, req.ip, fingerprint, expiresAt);

  res.cookie('sv_session', sessionToken, {
    httpOnly:  true,
    secure:    process.env.NODE_ENV === 'production',
    sameSite:  'strict',
    maxAge:    SESSION_SECS * 1000,
  });

  res.json({ success: true, redirect: '/vault-admin' });
});

module.exports = router;
