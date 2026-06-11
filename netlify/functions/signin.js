const {
  json, bad, parseBody,
  findAccount, verifyPassword, publicAccount,
} = require('./_shared');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);
  const { username, password } = parseBody(event);
  if (!username || !password) return bad('Enter your username and password.');

  const acct = await findAccount(username);
  if (!acct) return bad('No account found. Create one first.', 401);

  if (!verifyPassword(password, acct.pass_hash)) {
    return bad('Wrong password.', 401);
  }

  return json(200, { ok: true, account: publicAccount(acct) });
};
