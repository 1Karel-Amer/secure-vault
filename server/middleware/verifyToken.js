const jwt = require('jsonwebtoken');
const { createFingerprint } = require('./fingerprint');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-jwt-secret-change-in-production';

/**
 * Middleware: verifies the session JWT cookie.
 * Also checks device fingerprint — stolen tokens from different machines are rejected.
 */
function verifyToken(req, res, next) {
  const token = req.cookies?.sv_session;

  if (!token) {
    // No session — redirect to home (not to login, to avoid hinting at paths)
    return res.redirect('/');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.type !== 'session') {
      throw new Error('Invalid token type');
    }

    // ── Fingerprint check: reject if request comes from a different device ──
    const currentFingerprint = createFingerprint(req);
    if (decoded.fingerprint !== currentFingerprint) {
      console.log(`[SECURITY] Fingerprint mismatch — username: ${decoded.username}, ip: ${req.ip}`);
      res.clearCookie('sv_session');
      return res.status(403).json({ error: 'Session bound to different device. Access denied.' });
    }

    req.user = decoded;
    next();
  } catch (e) {
    res.clearCookie('sv_session');
    return res.redirect('/');
  }
}

module.exports = { verifyToken };
