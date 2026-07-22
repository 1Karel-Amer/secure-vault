const bcrypt = require('bcrypt');

// ── Load user registry from environment variables ──
let _users = null;

function loadUsers() {
  const users = {};
  for (let i = 1; i <= 4; i++) {
    const username     = process.env[`USER_${i}_USERNAME`];
    const passwordHash = process.env[`USER_${i}_PASSWORD_HASH`];
    const totpSecret   = process.env[`USER_${i}_TOTP_SECRET`];
    if (username && passwordHash && totpSecret) {
      users[username.toLowerCase()] = {
        username,
        passwordHash,
        totpSecret,
        isAdmin: i === 1,
      };
    }
  }
  return users;
}

function getUsers() {
  if (!_users) _users = loadUsers();
  return _users;
}

/**
 * Verifies the group passphrase against the bcrypt hash stored in env.
 */
async function verifyPassphrase(passphrase) {
  const hash = process.env.GROUP_PASSPHRASE_HASH;
  if (!hash) {
    console.error('[CRYPTO] GROUP_PASSPHRASE_HASH is not set!');
    return false;
  }
  return bcrypt.compare(passphrase, hash);
}

/**
 * Verifies a user's password. Runs bcrypt even on unknown usernames
 * to prevent timing-based username enumeration.
 */
async function verifyPassword(username, password) {
  const users = getUsers();
  const user  = users[username.toLowerCase()];

  if (!user) {
    // Dummy compare to waste attacker's time equally
    await bcrypt.compare(password, '$2b$12$invalidhashpadding0000000000000000000000000000000000');
    return false;
  }

  return bcrypt.compare(password, user.passwordHash);
}

function getUser(username) {
  const users = getUsers();
  return users[username.toLowerCase()] || null;
}

module.exports = { verifyPassphrase, verifyPassword, getUser };
