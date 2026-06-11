const {
  json, bad, parseBody,
  supa, findAccount, stripe, publicAccount,
} = require('./_shared');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);
  const { sessionId } = parseBody(event);
  if (!sessionId) return bad('Missing session id.');

  const pendRes = await supa(
    `/cnf_pending_signups?stripe_session_id=eq.${encodeURIComponent(sessionId)}&select=*`
  );
  if (!pendRes.ok || !pendRes.data?.[0]) return bad('Unknown checkout session.', 404);
  const pending = pendRes.data[0];

  // Idempotent: if already completed, just return the account.
  if (pending.status === 'completed') {
    const acct = await findAccount(pending.username);
    if (acct) return json(200, { ok: true, account: publicAccount(acct) });
    // fall through and try to recreate
  }

  // Verify the payment with Stripe.
  const ses = await stripe(`/checkout/sessions/${encodeURIComponent(sessionId)}`);
  if (!ses.ok || !ses.data) return bad('Could not verify payment.', 502);
  if (ses.data.payment_status !== 'paid') {
    return bad('Payment is not complete yet. If you just paid, try again in a moment.', 402);
  }

  const existing = await findAccount(pending.username);
  if (existing) {
    // Race: someone else grabbed the username after payment started.
    await supa(`/cnf_pending_signups?id=eq.${pending.id}`, {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'completed',
        completed_at: new Date().toISOString(),
      }),
    });
    return bad(
      'That username was taken right before payment finished. Contact the commissioner for a refund.',
      409
    );
  }

  const ins = await supa('/cnf_accounts', {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({
      username: pending.username,
      pass_hash: pending.pass_hash,
      avatar_data: pending.avatar_data,
      is_admin: false,
      security_q: pending.security_q,
      security_a_hash: pending.security_a_hash,
    }),
  });
  if (!ins.ok) return bad('Could not create account after payment. Contact commissioner.', 500);

  await supa(`/cnf_pending_signups?id=eq.${pending.id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      status: 'completed',
      completed_at: new Date().toISOString(),
    }),
  });

  return json(200, { ok: true, account: publicAccount(ins.data[0]) });
};
