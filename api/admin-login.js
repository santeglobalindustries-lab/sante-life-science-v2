// Verifies the Admin passcode and, if correct, mints a Firebase custom auth
// token carrying { role: 'admin' }. The database rules grant full access
// only to tokens with that claim — the passcode itself never reaches the
// browser's source code anymore (previously it was a plain constant sitting
// in index.html, visible to anyone who opened dev tools).
import { mintCustomToken, withJsonHandler } from './_firebaseAdmin.js';

export default withJsonHandler(async (body, res) => {
  const { passcode } = body;
  const expected = process.env.ADMIN_PASSCODE;
  if (!expected) {
    res.status(500).json({ error: 'Server is missing ADMIN_PASSCODE configuration.' });
    return;
  }
  if (!passcode || passcode !== expected) {
    res.status(401).json({ error: 'Incorrect passcode.' });
    return;
  }
  const token = mintCustomToken('admin-user', { role: 'admin' });
  res.status(200).json({ token });
});
