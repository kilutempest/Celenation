const {
  json, bad, parseBody,
  findAccount, verifyPassword, hashPassword, supa,
} = require('./_shared');

// Logged-in user changes their own password. Requires the current password
// for confirmation, just like a normal "change password" form.
exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);
  const { username, currentPassword, newPassword } = parseBody(event);

  if (!username || !currentPassword || !newPassword) {
    return bad('Missing fields.');
  }
  if (String(newPassword).length < 4) {
    return bad('New password must be at least 4 characters.');
  }
  if (String(newPassword) === String(currentPassword)) {
    return bad('New password is the same as the current one.');
  }

  const acct = await findAccount(username);
  if (!acct) return bad('Account not found.', 404);
  if (!verifyPassword(currentPassword, acct.pass_hash)) {
    return bad('Current password is wrong.', 401);
  }

  const newHash = hashPassword(newPassword);
  const upd = await supa(
    `/cnf_accounts?username=eq.${encodeURIComponent(acct.username)}`,
    {
      method: 'PATCH',
      body: JSON.stringify({
        pass_hash: newHash,
        updated_at: new Date().toISOString(),
      }),
    }
  );
  if (!upd.ok) return bad('Could not update password.', 500);

  return json(200, { ok: true });
};
