// Called both when a device that already remembers an account reopens the
// app, and when someone picks "Unlock" after entering a phone number that
// turned out to already be bound. Either way: no Firebase identity exists
// yet at this point, so this has to be a server call.
import { adminDb, withJsonHandler } from '../_firebaseAdmin.js';
import { generateAuthenticationOptions } from '@simplewebauthn/server';

export default withJsonHandler(async (body, res) => {
  const { doctorId, accountKey } = body;
  if (!doctorId || !accountKey) {
    res.status(400).json({ error: 'Missing fields.' });
    return;
  }
  const db = adminDb();
  const accSnap = await db.ref(`doctors/${doctorId}/accounts/${accountKey}`).once('value');
  const acc = accSnap.val();
  if (!acc || !acc.bound || !acc.credential) {
    res.status(200).json({ bound: false });
    return;
  }

  const rpID = process.env.RP_ID;
  if (!rpID) {
    res.status(500).json({ error: 'Server is missing RP_ID configuration.' });
    return;
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [{ id: acc.credential.id }],
    userVerification: 'preferred',
  });

  await db.ref(`webauthnChallenges/${doctorId}_${accountKey}`).set({
    challenge: options.challenge,
    purpose: 'login',
    createdAt: Date.now(),
  });

  res.status(200).json({ bound: true, label: acc.label || accountKey, options });
});
