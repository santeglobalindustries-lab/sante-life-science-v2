// Before someone logs in, the browser has no Firebase identity yet, so under
// the locked-down database rules it can't read the doctors list at all (not
// even to check "does this phone number belong to anyone"). This endpoint
// does that lookup server-side, using the admin credential, and returns only
// the minimum needed to continue the login flow — never the PIN hash or the
// stored public key.
const { adminDb, withJsonHandler } = require('./_firebaseAdmin');

module.exports = withJsonHandler(async (body, res) => {
  const cleanPhone = String(body.phone || '').replace(/[^\d]/g, '');
  if (!cleanPhone) {
    res.status(400).json({ error: 'Enter your number.' });
    return;
  }
  const snap = await adminDb().ref('doctors').once('value');
  const doctors = snap.val() || {};
  for (const doctorId of Object.keys(doctors)) {
    const accounts = (doctors[doctorId] && doctors[doctorId].accounts) || {};
    for (const accountKey of Object.keys(accounts)) {
      const acc = accounts[accountKey] || {};
      const accPhone = String(acc.phone || '').replace(/[^\d]/g, '');
      if (accPhone && accPhone.slice(-10) === cleanPhone.slice(-10)) {
        res.status(200).json({
          doctorId,
          accountKey,
          label: acc.label || accountKey,
          bound: !!acc.bound,
          hasPendingPin: !!acc.pinHash,
        });
        return;
      }
    }
  }
  res.status(404).json({ error: 'No account found with this number. Ask the Sante team to add it.' });
});
