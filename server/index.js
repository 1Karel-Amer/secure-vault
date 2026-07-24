require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const path = require('path');
const { initDatabase } = require('./db/database');

const app = express();

// ── Trust Render's proxy so req.ip returns the real client IP ──
app.set('trust proxy', 1);

// ── Remove X-Powered-By to hide stack info ──
app.disable('x-powered-by');

// ── Strict security headers via helmet ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:    ["'self'", "'unsafe-inline'"],
      imgSrc:      ["'self'", "data:"],
      connectSrc:  ["'self'"],
      fontSrc:     ["'self'"],
      objectSrc:   ["'none'"],
      frameSrc:    ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'fallback-cookie-secret'));

// ── Serve only public/ (decoy + landing) — no directory listing ──
app.use(express.static(path.join(__dirname, '../public'), {
  index: false,
  dotfiles: 'deny',
  extensions: false,
}));

// ── Routes ──
const honeypotRouter = require('./routes/honeypot');
const authRouter     = require('./routes/auth');
const adminRouter    = require('./routes/admin');

// Landing page — generic, gives nothing away
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// robots.txt — hints at clue.txt (hackers always check this)
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send('User-agent: *\nDisallow: /vault-admin\n\n# Looking for something? Try /clue.txt');
});

// clue.txt — CTF hint pointing to the blog
app.get('/clue.txt', (req, res) => {
  res.type('text/plain');
  res.send('\uD83D\uDC3E CLUE #1\n\nThe door you\'re looking for isn\'t where you\'d expect.\nStart where the cats roam freely.\nRead carefully \u2014 members know where to go.\n\nGood luck. \uD83D\uDC31');
});

// Honeypot: visible, obvious, traps attackers
app.use('/login', honeypotRouter);

// Real auth: hidden path stored only in env var
const REAL_AUTH_PATH = process.env.REAL_AUTH_PATH || '/sv/g8te';
app.use(REAL_AUTH_PATH, authRouter);

// Cat-themed alias → silently redirects to real portal (share this with your group)
app.get('/cats/members-area', (req, res) => {
  res.redirect(REAL_AUTH_PATH);
});

// Admin dashboard: requires valid session cookie
app.use('/vault-admin', adminRouter);

// ── 404: reveal nothing useful ──
app.use((req, res) => {
  res.status(404).send('Not Found');
});

// ── Error handler ──
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).send('Internal Server Error');
});

const PORT = process.env.PORT || 3000;
initDatabase();
app.listen(PORT, () => {
  console.log(`[SERVER] Running on port ${PORT}`);
  console.log(`[SERVER] Real auth path active (hidden)`);
});
