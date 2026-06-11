const crypto = require('crypto');
const { json, bad, supa, findAccount } = require('./_shared');

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

function verifySignature(rawBody, header, secret, toleranceSec = 300) {
  if (!header || !secret) return false;
  const parts = {};
  for (const piece of header.split(',')) {
    const ix = piece.indexOf('=');
    if (ix < 0) continue;
    parts[piece.slice(0, ix).trim()] = piece.slice(ix + 1).trim();
  }
  const ts = parts.t;
  const v1 = parts.v1;
  if (!ts || !v1) return false;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${ts}.${rawBody}`)
    .digest('hex');
  let ok = false;
  try {
    ok = crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(v1, 'hex'));
  } catch (e) {
    return false;
  }
  if (!ok) return false;
  const age = Math.floor(Date.now() / 1000) - parseInt(ts, 10);
  return Math.abs(age) <= toleranceSec;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);

  const sig =
    (event.headers && (event.headers['stripe-signature'] || event.headers['Stripe-Signature'])) ||
    '';
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body || '', 'base64').toString('utf8')
    : (event.body || '');

  if (!verifySignature(raw, sig, WEBHOOK_SECRET)) {
    return bad('Bad signature', 400);
  }

  let payload;
  try { payload = JSON.parse(raw); }
  catch (e) { return bad('Bad JSON', 400); }

  if (payload.type !== 'checkout.session.completed') {
    return json(200, { received: true });
  }

  const session = payload.data?.object;
  const pendingId = session?.metadata?.pending_id;
  if (!pendingId) return json(200, { received: true });

  const pendRes = await supa(
    `/cnf_pending_signups?id=eq.${encodeURIComponent(pendingId)}&select=*`
  );
  const pending = pendRes.data?.[0];
  if (!pending) return json(200, { received: true });
  if (pending.status === 'completed') return json(200, { received: true });

  const existing = await findAccount(pending.username);
  if (!existing) {
    await supa('/cnf_accounts', {
      method: 'POST',
      body: JSON.stringify({
        username: pending.username,
        pass_hash: pending.pass_hash,
        avatar_data: pending.avatar_data,
        is_admin: false,
        security_q: pending.security_q,
        security_a_hash: pending.security_a_hash,
      }),
    });
  }

  await supa(`/cnf_pending_signups?id=eq.${pending.id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      status: 'completed',
      completed_at: new Date().toISOString(),
    }),
  });

  return json(200, { received: true });
};
