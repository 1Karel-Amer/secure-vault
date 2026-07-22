const rateLimit = require('express-rate-limit');
const db        = require('../db/database');

/**
 * Auth limiter: 10 requests per 10 minutes per IP.
 * Defeats Hydra and all brute-force tools.
 * Also auto-bans the IP in our DB on trigger.
 */
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  standardHeaders: false,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    console.log(`[RATE_LIMIT] Blocked ${req.ip} on ${req.path}`);
    db.banIp(req.ip, 30 * 60 * 1000, 'Rate limit exceeded on auth endpoint');
    res.status(429).json({ error: 'Too many requests. You have been temporarily blocked.' });
  },
});

module.exports = { authLimiter };
