// This is the function that actually proves "this really is the person who
// registered this fingerprint" — verifying a cryptographic signature against
// the public key stored at registration time, not just comparing an ID
// string. Only once that check passes does the caller get a real,
// doctor-scoped identity token.
import { adminDb, mintCustomToken, withJsonHandler } from '../_firebaseAdmin.js';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

const CHALLENGE_MAX_AGE_MS = 5 * 60 * 1000;

export default withJsonHandler(async (body, res) => {
  const { doctorId, accountKey, response } = body;
  if (!doctorId || !accountKey || !response) {
    res.status(400).json({ error: 'Missing fields.' });
    return;
  }
  const db = adminDb();
  const accRef = db.ref(`doctors/${doctorId}/accounts/${accountKey}`);
  const accSnap = await accRef.once('value');
  const acc = accSnap.val();
  if (!acc || !acc.bound || !acc.credential) {
    res.status(400).json({ error: 'This account is not set up for fingerprint login.' });
    return;
  }

  const challengeRef = db.ref(`webauthnChallenges/${doctorId}_${accountKey}`);
  const challengeSnap = await challengeRef.once('value');
  const stored = challengeSnap.val();
  if (!stored || stored.purpose !== 'login' || Date.now() - stored.createdAt > CHALLENGE_MAX_AGE_MS) {
    res.status(400).json({ error: 'This login attempt expired. Please try again.' });
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
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: stored.challenge,
      expectedOrigin: origins,
      expectedRPID: rpID,
      credential: {
        id: acc.credential.id,
        publicKey: Buffer.from(acc.credential.publicKey, 'base64'),
        counter: acc.credential.counter,
      },
    });
  } catch (err) {
    res.status(400).json({ error: "That didn't match this account's fingerprint. Try again." });
    return;
  }
  if (!verification.verified) {
    res.status(400).json({ error: "That didn't match this account's fingerprint. Try again." });
    return;
  }

  // Keep the replay-attack counter current for next time.
  await accRef.child('credential/counter').set(verification.authenticationInfo.newCounter);
  await challengeRef.remove();

  const token = mintCustomToken(`${doctorId}_${accountKey}`, {
    role: 'doctor',
    doctorId,
    accountKey,
  });
  res.status(200).json({ token, accountLabel: acc.label || accountKey });
});
