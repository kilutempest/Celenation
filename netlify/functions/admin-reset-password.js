const {
  json, bad, parseBody,
  findAccount, verifyPassword, hashPassword, supa,
} = require('./_shared');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);
  const { adminUsername, adminPassword, targetUsername, newPassword } = parseBody(event);
  if (!adminUsername || !adminPassword || !targetUsername || !newPassword) {
    return bad('Missing fields.');
  }
  if (String(newPassword).length < 4) return bad('New password must be at least 4 characters.');

  const admin = await findAccount(adminUsername);
  if (!admin || !admin.is_admin) return bad('Not authorized.', 403);
  if (!verifyPassword(adminPassword, admin.pass_hash)) {
    return bad('Admin password is wrong.', 401);
  }

  const target = await findAccount(targetUsername);
  if (!target) return bad('Target account not found.', 404);

  const newHash = hashPassword(newPassword);
  const upd = await supa(
    `/cnf_accounts?username=eq.${encodeURIComponent(target.username)}`,
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
