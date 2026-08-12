// Second step of fingerprint/Face ID setup. Verifies the cryptographic
// attestation the browser produced against the challenge we generated a
// moment ago, and — critically — stores the credential's PUBLIC key (not
// just an ID string) so future logins can be verified with a real
// signature check, not just "does this ID match".
const { adminDb, adminAuth, withJsonHandler } = require('../_firebaseAdmin');
const { verifyRegistrationResponse } = require('@simplewebauthn/server');

const CHALLENGE_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes to complete the biometric prompt

module.exports = withJsonHandler(async (body, res) => {
  const { doctorId, accountKey, response } = body;
  if (!doctorId || !accountKey || !response) {
    res.status(400).json({ error: 'Missing fields.' });
    return;
  }
  const db = adminDb();
  const challengeRef = db.ref(`webauthnChallenges/${doctorId}_${accountKey}`);
  const challengeSnap = await challengeRef.once('value');
  const stored = challengeSnap.val();
  if (!stored || stored.purpose !== 'register' || Date.now() - stored.createdAt > CHALLENGE_MAX_AGE_MS) {
    res.status(400).json({ error: 'This setup attempt expired. Please try again.' });
    return;
  }

  const rpID = process.env.RP_ID;
  const origins = (process.env.ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!rpID || !origins.length) {
    res.status(500).json({ error: 'Server is missing RP_ID/ORIGIN configuration.' });
    return;
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: stored.challenge,
      expectedOrigin: origins,
      expectedRPID: rpID,
    });
  } catch (err) {
    res.status(400).json({ error: 'Fingerprint verification failed: ' + err.message });
    return;
  }
  if (!verification.verified || !verification.registrationInfo) {
    res.status(400).json({ error: 'Fingerprint could not be verified. Please try again.' });
    return;
  }

  const { credential } = verification.registrationInfo;
  await db.ref(`doctors/${doctorId}/accounts/${accountKey}`).update({
    credential: {
      id: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64'),
      counter: credential.counter,
    },
    bound: true,
    pinHash: null,
  });
  await challengeRef.remove();

  const accSnap = await db.ref(`doctors/${doctorId}/accounts/${accountKey}`).once('value');
  const acc = accSnap.val();
  const token = await adminAuth().createCustomToken(`${doctorId}_${accountKey}`, {
    role: 'doctor',
    doctorId,
    accountKey,
  });
  res.status(200).json({ token, accountLabel: acc.label || accountKey });
});
