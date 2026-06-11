const {
  json, bad, parseBody,
  findAccount, verifyPassword, hashPassword, normalizeAnswer, supa,
} = require('./_shared');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);
  const { username, answer, newPassword } = parseBody(event);
  if (!username || !answer || !newPassword) return bad('Missing fields.');
  if (String(newPassword).length < 4) return bad('New password must be at least 4 characters.');

  const acct = await findAccount(username);
  if (!acct || !acct.security_a_hash) return bad('Account or recovery info not found.', 404);

  if (!verifyPassword(normalizeAnswer(answer), acct.security_a_hash)) {
    return bad('Wrong answer to security question.', 401);
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
