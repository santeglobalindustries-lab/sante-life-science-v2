// Shared setup for every serverless function under /api. Runs SERVER-SIDE
// ONLY (on Vercel), never shipped to the browser, using a service account
// credential read from environment variables you configure in Vercel's
// dashboard (Settings → Environment Variables) — never committed to git.
//
// Note on why this doesn't use firebase-admin's auth module: getAuth() from
// firebase-admin/auth pulls in a dependency chain (jwks-rsa → jose) that
// crashes specifically inside Vercel's build/bundling pipeline with
// "ERR_REQUIRE_ESM" — confirmed this still happens even when this project's
// own code is written as ES modules, because the crash originates inside
// that dependency's own bundled output, not in code we control. Rather than
// fight Vercel's bundler, mintCustomToken() below builds the exact same
// JWT structure the Admin SDK would (Firebase's publicly documented custom
// token format: https://firebase.google.com/docs/auth/admin/create-custom-tokens),
// signed with Node's built-in crypto module — no extra dependency, no
// import of the problematic module at all.
import { cert, initializeApp, getApps } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import crypto from 'crypto';

function readCredentials() {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const databaseURL = process.env.FIREBASE_DATABASE_URL;
  const rawKey = process.env.FIREBASE_PRIVATE_KEY || '';
  // Environment variable UIs are surprisingly easy to paste a key into
  // slightly wrong — a stray leading/trailing space, the whole value
  // wrapped in quotes, or literal "\n" text instead of real line breaks —
  // and every one of those makes Node's crypto library reject the key with
  // an opaque "DECODER routines::unsupported" error. This normalizes all
  // of those cases rather than requiring the paste to be pixel-perfect.
  const privateKey = rawKey
    .trim()
    .replace(/^"(.*)"$/s, '$1')   // strip a single pair of surrounding quotes, if present
    .replace(/\\n/g, '\n')        // literal backslash-n -> real newline
    .replace(/\r\n/g, '\n')       // CRLF -> LF
    .trim();
  if (!projectId || !clientEmail || !privateKey || !databaseURL) {
    throw new Error(
      'Missing Firebase Admin environment variables. Required: FIREBASE_PROJECT_ID, ' +
      'FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, FIREBASE_DATABASE_URL.'
    );
  }
  if (!privateKey.startsWith('-----BEGIN PRIVATE KEY-----')) {
    throw new Error(
      'FIREBASE_PRIVATE_KEY does not look like a valid PEM private key (should start with ' +
      '"-----BEGIN PRIVATE KEY-----"). Re-check the value pasted into Vercel.'
    );
  }
  return { projectId, clientEmail, privateKey, databaseURL };
}

function getAdminApp() {
  if (getApps().length) return getApps()[0];
  const { projectId, clientEmail, privateKey, databaseURL } = readCredentials();
  return initializeApp({ credential: cert({ projectId, clientEmail, privateKey }), databaseURL });
}

export function adminDb() {
  return getDatabase(getAdminApp());
}

function base64url(bufOrStr) {
  const buf = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(bufOrStr);
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Mints a Firebase custom auth token carrying the given uid + custom claims.
// The client exchanges this via firebase.auth().signInWithCustomToken(),
// and the database rules check the resulting token's claims (role,
// doctorId, accountKey) to enforce who can read/write what.
export function mintCustomToken(uid, claims) {
  const { clientEmail, privateKey } = readCredentials();
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: clientEmail,
    sub: clientEmail,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now,
    exp: now + 3600,
    uid,
    claims: claims || {},
  };
  const unsigned = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(payload));
  const signature = crypto.createSign('RSA-SHA256').update(unsigned).sign(privateKey);
  return unsigned + '.' + base64url(signature);
}

// Small helper so every function handles method/body parsing and error
// responses the same consistent way.
export function withJsonHandler(fn) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') {
      res.status(405).json({ error: 'Method not allowed.' });
      return;
    }
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body || '{}'); } catch (e) { body = {}; }
    }
    try {
      await fn(body || {}, res, req);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error: ' + err.message });
    }
  };
}
