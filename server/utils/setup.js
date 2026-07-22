/**
 * SECURE VAULT — Setup Script
 * Run this ONCE locally before deploying:
 *   npm run setup
 *
 * It will:
 *  1. Ask for group passphrase and user credentials
 *  2. Hash everything with bcrypt (cost 12)
 *  3. Generate TOTP secrets + QR code PNGs for Google Authenticator
 *  4. Write a .env file with all the hashed values
 *  5. You then copy .env values to Render dashboard and DELETE the local .env
 */

require('dotenv').config();
const bcrypt    = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode    = require('qrcode');
const readline  = require('readline');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const question = (prompt) => new Promise(resolve => rl.question(prompt, resolve));

async function main() {
  console.log('\n╔══════════════════════════════════════╗');
  console.log('║       SECURE VAULT — SETUP           ║');
  console.log('╚══════════════════════════════════════╝\n');

  const envLines = [];

  // ── Generate cryptographic secrets ──
  console.log('[ 1/4 ] Generating cryptographic secrets...');
  const jwtSecret    = crypto.randomBytes(64).toString('hex');
  const stepSecret   = crypto.randomBytes(64).toString('hex');
  const cookieSecret = crypto.randomBytes(32).toString('hex');
  envLines.push(`JWT_SECRET=${jwtSecret}`);
  envLines.push(`STEP_TOKEN_SECRET=${stepSecret}`);
  envLines.push(`COOKIE_SECRET=${cookieSecret}`);
  envLines.push(`NODE_ENV=production`);
  console.log('  ✓ JWT_SECRET, STEP_TOKEN_SECRET, COOKIE_SECRET generated\n');

  // ── Group passphrase ──
  console.log('[ 2/4 ] Group Passphrase');
  console.log('  This is the shared secret ALL members must enter first.');
  const passphrase     = await question('  Enter group passphrase: ');
  const passphraseHash = await bcrypt.hash(passphrase.trim(), 12);
  envLines.push(`GROUP_PASSPHRASE_HASH=${passphraseHash}`);
  console.log('  ✓ Passphrase hashed with bcrypt (cost 12)\n');

  // ── Hidden auth path ──
  console.log('[ 3/4 ] Hidden Auth URL Path');
  console.log('  This is the secret URL path to the real login page.');
  console.log('  Avoid common words. Example: /sv/g8te  or  /x9k2-access');
  const hiddenPath = (await question('  Enter hidden path (press Enter for /sv/g8te): ')).trim();
  envLines.push(`REAL_AUTH_PATH=${hiddenPath || '/sv/g8te'}`);
  console.log(`  ✓ Auth path set\n`);

  // ── Users ──
  console.log('[ 4/4 ] User Accounts');
  const numStr   = (await question('  How many members? (1-4): ')).trim();
  const numUsers = Math.min(Math.max(parseInt(numStr, 10) || 1, 1), 4);

  const qrDir = path.join(__dirname, '../../qr-codes');
  if (!fs.existsSync(qrDir)) fs.mkdirSync(qrDir, { recursive: true });

  for (let i = 1; i <= numUsers; i++) {
    console.log(`\n  ── User ${i} ──`);
    const username = (await question(`    Username: `)).trim();
    const password = (await question(`    Password: `)).trim();

    const passwordHash = await bcrypt.hash(password, 12);
    const totpData     = speakeasy.generateSecret({
      name:   `SecureVault:${username}`,
      issuer: 'SecureVault',
      length: 20,
    });

    envLines.push(`USER_${i}_USERNAME=${username}`);
    envLines.push(`USER_${i}_PASSWORD_HASH=${passwordHash}`);
    envLines.push(`USER_${i}_TOTP_SECRET=${totpData.base32}`);

    // Save QR code PNG
    const qrPath = path.join(qrDir, `${username}-totp.png`);
    await qrcode.toFile(qrPath, totpData.otpauth_url);
    console.log(`    ✓ QR code saved → qr-codes/${username}-totp.png`);
    console.log(`    📱 Open the PNG and scan with Google Authenticator`);
  }

  // ── Write .env ──
  const envPath = path.join(__dirname, '../../.env');
  fs.writeFileSync(envPath, envLines.join('\n') + '\n', 'utf8');

  console.log('\n╔══════════════════════════════════════╗');
  console.log('║            SETUP COMPLETE            ║');
  console.log('╚══════════════════════════════════════╝');
  console.log('\n📋 NEXT STEPS:');
  console.log('  1. Open qr-codes/ and scan each PNG with Google Authenticator');
  console.log('  2. Open .env and copy EACH variable to Render dashboard');
  console.log('     → render.com → Your Service → Environment → Add Env Var');
  console.log('  3. After copying to Render, DELETE the local .env file');
  console.log('  4. The qr-codes/ folder is in .gitignore — do NOT share these PNGs');
  console.log('  5. Push code to GitHub → Render auto-deploys\n');

  rl.close();
}

main().catch((err) => {
  console.error('\n[SETUP ERROR]', err.message);
  process.exit(1);
});
