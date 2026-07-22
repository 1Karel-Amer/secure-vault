const speakeasy = require('speakeasy');
const { getUser } = require('./crypto');

// Track recently used TOTP tokens per user to prevent replay attacks
const usedTokens = new Map(); // username => Set of used tokens (cleared every 2 minutes)

setInterval(() => usedTokens.clear(), 2 * 60 * 1000);

/**
 * Verifies a TOTP code for a given user.
 * - Uses speakeasy with a ±1 window to handle clock drift
 * - Prevents replay: same code cannot be used twice within its validity window
 */
function verifyTOTP(username, token) {
  const user = getUser(username);
  if (!user || !user.totpSecret) return false;

  const cleanToken = token.toString().replace(/\s/g, '');

  // Check replay protection
  const key = `${username}:${cleanToken}`;
  if (!usedTokens.has(username)) usedTokens.set(username, new Set());
  if (usedTokens.get(username).has(cleanToken)) {
    console.log(`[TOTP] Replay attempt blocked for user: ${username}`);
    return false;
  }

  const valid = speakeasy.totp.verify({
    secret:   user.totpSecret,
    encoding: 'base32',
    token:    cleanToken,
    window:   1, // Allow 1 step (30s) before/after for clock drift
  });

  if (valid) {
    // Mark this token as used
    usedTokens.get(username).add(cleanToken);
  }

  return valid;
}

module.exports = { verifyTOTP };
