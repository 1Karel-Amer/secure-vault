const express   = require('express');
const router    = express.Router();
const rateLimit = require('express-rate-limit');
const path      = require('path');
const db        = require('../db/database');

// ── Very strict rate limiter for honeypot (3 tries per hour) ──
const honeypotLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: false,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    db.logHoneypot(req.ip, req.body?.username || '[rate-limit]', req.get('User-Agent') || '', 'rate-limit');
    db.banIp(req.ip, 2 * 60 * 60 * 1000, 'Rate limit exceeded on honeypot');
    res.status(429).json({ error: 'Too many attempts. Try again later.' });
  },
});

// ── GET /login — Serve the decoy login page ──
router.get('/', (req, res) => {
  db.logHoneypot(req.ip, '[page-visit]', req.get('User-Agent') || '', 'visit');
  res.sendFile(path.join(__dirname, '../../public/login.html'));
});

// ── POST /login — Trap any login attempt ──
router.post('/', honeypotLimiter, (req, res) => {
  const username = req.body?.username || '';
  db.logHoneypot(req.ip, username, req.get('User-Agent') || '', 'attempt');
  db.banIp(req.ip, 60 * 60 * 1000, 'Honeypot login attempt');

  // Slow response to waste brute-force tool time
  const delay = 2000 + Math.random() * 1500;
  setTimeout(() => {
    res.status(401).json({ error: 'Invalid credentials' });
  }, delay);
});

module.exports = router;
