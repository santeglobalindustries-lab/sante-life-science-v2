// Shared Firebase Admin SDK setup for every serverless function under /api.
// This runs SERVER-SIDE ONLY (on Vercel), never shipped to the browser, and
// uses a service account credential — read from environment variables you
// configure in Vercel's dashboard (Settings → Environment Variables), never
// committed to git. This is what gives these functions full, unrestricted
// access to Firebase regardless of the database security rules, so they can
// safely do things like verify a PIN or a fingerprint assertion and then
// mint a properly-scoped identity token for that specific doctor.
const { cert, initializeApp, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getDatabase } = require('firebase-admin/database');

function getAdminApp() {
  if (getApps().length) return getApps()[0];

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  // Vercel env vars store literal text, so a real private key's newlines
  // arrive as the two characters "\" and "n" rather than an actual newline.
  // This converts them back before handing the key to the crypto library.
  const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  const databaseURL = process.env.FIREBASE_DATABASE_URL;

  if (!projectId || !clientEmail || !privateKey || !databaseURL) {
    throw new Error(
      'Missing Firebase Admin environment variables. Required: FIREBASE_PROJECT_ID, ' +
      'FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, FIREBASE_DATABASE_URL.'
    );
  }

  return initializeApp({
    credential: cert({ projectId, clientEmail, privateKey }),
    databaseURL,
  });
}

function adminAuth() {
  return getAuth(getAdminApp());
}
function adminDb() {
  return getDatabase(getAdminApp());
}

// Small helper so every function handles method/body parsing and error
// responses the same consistent way.
function withJsonHandler(fn) {
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

module.exports = { adminAuth, adminDb, withJsonHandler };
