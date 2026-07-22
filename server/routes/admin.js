const express = require('express');
const router  = express.Router();
const path    = require('path');
const { verifyToken } = require('../middleware/verifyToken');
const db              = require('../db/database');

// ── All admin routes require a valid session JWT ──
router.use(verifyToken);

// ── GET /vault-admin — Serve the admin dashboard ──
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../views/dashboard.html'));
});

router.get('/api/me', (req, res) => {
  res.json({ username: req.user.username });
});

router.get('/api/honeypot-logs', (req, res) => {
  res.json(db.getHoneypotLogs(200));
});

router.get('/api/auth-logs', (req, res) => {
  res.json(db.getAuthLogs(200));
});

router.get('/api/banned-ips', (req, res) => {
  res.json(db.getBannedIps());
});

router.get('/api/sessions', (req, res) => {
  const sessions = db.getActiveSessions();
  res.json({ count: sessions.length, sessions });
});

router.get('/api/stats', (req, res) => {
  res.json(db.getStats());
});

router.post('/logout', (req, res) => {
  res.clearCookie('sv_session');
  res.json({ success: true });
});

module.exports = router;
