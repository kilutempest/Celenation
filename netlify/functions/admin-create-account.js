const {
  json, bad, parseBody,
  findAccount, verifyPassword, hashPassword, supa, publicAccount,
} = require('./_shared');

// Admin-only: creates a paid-equivalent account without payment.
// Used by the commissioner to grant free access to specific players.
exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);
  const {
    adminUsername, adminPassword,
    targetUsername, targetPassword, targetIsAdmin,
  } = parseBody(event);

  if (!adminUsername || !adminPassword || !targetUsername || !targetPassword) {
    return bad('Missing fields.');
  }
  if (String(targetPassword).length < 4) {
    return bad('Target password must be at least 4 characters.');
  }

  const admin = await findAccount(adminUsername);
  if (!admin || !admin.is_admin) return bad('Not authorized.', 403);
  if (!verifyPassword(adminPassword, admin.pass_hash)) {
    return bad('Admin password is wrong.', 401);
  }

  const cleanUsername = String(targetUsername).trim().replace(/\s+/g, '_');
  if (cleanUsername.length < 2) return bad('Target username must be at least 2 characters.');

  const existing = await findAccount(cleanUsername);
  if (existing) return bad('That username already exists.', 409);

  // Recipient can change their password later by asking the admin to reset it
  // (Reset a Player's Password card). They can sign in immediately with the
  // credentials the admin shares with them.
  const passHash = hashPassword(targetPassword);
  const placeholderAns = hashPassword('admin-granted-' + Date.now());

  const ins = await supa('/cnf_accounts', {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({
      username: cleanUsername,
      pass_hash: passHash,
      avatar_data: null,
      is_admin: !!targetIsAdmin,
      security_q: 'Ask the commissioner to reset your password.',
      security_a_hash: placeholderAns,
    }),
  });
  if (!ins.ok) {
    if (ins.status === 409) return bad('That username already exists.', 409);
    return bad('Could not create account.', 500);
  }

  return json(200, { ok: true, account: publicAccount(ins.data[0]) });
};
