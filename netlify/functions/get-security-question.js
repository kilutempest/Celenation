const { json, bad, parseBody, findAccount } = require('./_shared');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);
  const { username } = parseBody(event);
  if (!username) return bad('Enter a username.');

  const acct = await findAccount(username);
  if (!acct || !acct.security_q) {
    return bad('No recovery question is set for that account.', 404);
  }
  return json(200, { question: acct.security_q });
};
