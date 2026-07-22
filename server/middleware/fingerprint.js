const crypto = require('crypto');

/**
 * Creates a SHA-256 fingerprint from browser/client characteristics.
 * Bound to the JWT session — stolen tokens won't work from a different machine.
 */
function createFingerprint(req) {
  const components = [
    req.get('User-Agent')       || 'no-ua',
    req.get('Accept-Language')  || 'no-lang',
    req.get('Accept-Encoding')  || 'no-enc',
    req.get('Accept')           || 'no-accept',
  ].join('||');

  return crypto.createHash('sha256').update(components).digest('hex');
}

module.exports = { createFingerprint };
