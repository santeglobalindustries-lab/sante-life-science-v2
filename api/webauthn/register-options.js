// First step of setting up fingerprint/Face ID login. The one-time password
// (PIN) is now checked here, server-side, instead of in the browser — so the
// stored PIN hash is never sent to any client at all, closing a gap where it
// would previously have been readable by anyone with open database access.
import crypto from 'crypto';
import { adminDb, withJsonHandler } from '../_firebaseAdmin.js';
import { generateRegistrationOptions } from '@simplewebauthn/server';

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

export default withJsonHandler(async (body, res) => {
  const { doctorId, accountKey, pin } = body;
  if (!doctorId || !accountKey || !pin) {
    res.status(400).json({ error: 'Missing fields.' });
    return;
  }
  const db = adminDb();
  const accSnap = await db.ref(`doctors/${doctorId}/accounts/${accountKey}`).once('value');
  const acc = accSnap.val();
  if (!acc) {
    res.status(404).json({ error: 'Account not found.' });
    return;
  }
  if (!acc.pinHash || sha256Hex(pin) !== acc.pinHash) {
    res.status(401).json({ error: 'Incorrect one-time password.' });
    return;
  }

  const rpID = process.env.RP_ID;
  if (!rpID) {
    res.status(500).json({ error: 'Server is missing RP_ID configuration.' });
    return;
  }

  const options = await generateRegistrationOptions({
    rpName: 'Sante Life Science',
    rpID,
    userName: `${doctorId}-${accountKey}`,
    userDisplayName: acc.label || accountKey,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
      authenticatorAttachment: 'platform',
    },
  });

  await db.ref(`webauthnChallenges/${doctorId}_${accountKey}`).set({
    challenge: options.challenge,
    purpose: 'register',
    createdAt: Date.now(),
  });

  res.status(200).json({ options });
});
