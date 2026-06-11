const {
  json, bad, parseBody,
  hashPassword, normalizeAnswer,
  supa, findAccount, stripe, publicAccount,
} = require('./_shared');

const SITE_URL = (process.env.SITE_URL || '').replace(/\/$/, '');
const PRICE_CENTS = parseInt(process.env.SIGNUP_PRICE_CENTS || '3500', 10);
const ADMIN_CODE = process.env.ADMIN_BYPASS_CODE || '';

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return bad('POST only', 405);

  const body = parseBody(event);
  const username = String(body.username || '').trim().replace(/\s+/g, '_');
  const password = String(body.password || '');
  const avatar = body.avatar ? String(body.avatar) : null;
  const securityQ = String(body.securityQ || '').trim();
  const securityA = String(body.securityA || '').trim();
  const adminCode = body.adminCode ? String(body.adminCode).trim() : '';

  if (username.length < 2) return bad('Username must be at least 2 characters.');
  if (password.length < 4) return bad('Password must be at least 4 characters.');
  if (securityQ.length < 4) return bad('Pick a security question.');
  if (securityA.length < 1) return bad('Answer your security question.');
  if (avatar && avatar.length > 2_800_000) return bad('Avatar image is too large.');

  const existing = await findAccount(username);
  if (existing) return bad('That username is taken. Sign in instead.');

  const passHash = hashPassword(password);
  const ansHash = hashPassword(normalizeAnswer(securityA));

  // Admin bypass — skip Stripe entirely.
  if (adminCode && ADMIN_CODE && adminCode === ADMIN_CODE) {
    const ins = await supa('/cnf_accounts', {
      method: 'POST',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify({
        username,
        pass_hash: passHash,
        avatar_data: avatar,
        is_admin: true,
        security_q: securityQ,
        security_a_hash: ansHash,
      }),
    });
    if (!ins.ok) {
      if (ins.status === 409) return bad('That username was just taken. Try another.');
      return bad('Could not create admin account.');
    }
    return json(200, { accountCreated: true, account: publicAccount(ins.data[0]) });
  }

  // Reject a bad code outright — don't silently treat it as a normal signup.
  if (adminCode) return bad('Invalid admin code.');

  // Sanity-check required env vars up front so the failure mode is obvious.
  const missing = [];
  if (!process.env.SUPABASE_URL) missing.push('SUPABASE_URL');
  if (!process.env.SUPABASE_SERVICE_KEY) missing.push('SUPABASE_SERVICE_KEY');
  if (!process.env.STRIPE_SECRET_KEY) missing.push('STRIPE_SECRET_KEY');
  if (!SITE_URL) missing.push('SITE_URL');
  if (missing.length) {
    return bad('Server missing env vars: ' + missing.join(', '), 500);
  }

  // Park the form data, then send the browser to Stripe Checkout.
  const pend = await supa('/cnf_pending_signups', {
    method: 'POST',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({
      username,
      pass_hash: passHash,
      avatar_data: avatar,
      security_q: securityQ,
      security_a_hash: ansHash,
    }),
  });
  if (!pend.ok || !pend.data?.[0]) {
    console.error('Supabase pending insert failed', pend.status, pend.data);
    const detail = (pend.data && (pend.data.message || pend.data.error || JSON.stringify(pend.data).slice(0,200))) || 'no detail';
    return bad(`Supabase rejected pending signup (status ${pend.status}): ${detail}`, 500);
  }
  const pendingId = pend.data[0].id;

  const cs = await stripe('/checkout/sessions', {
    mode: 'payment',
    'line_items[0][quantity]': 1,
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][unit_amount]': PRICE_CENTS,
    'line_items[0][price_data][product_data][name]': 'CeleNation Fantasy — Season Access',
    success_url: `${SITE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${SITE_URL}/?canceled=1`,
    metadata: { pending_id: pendingId, username },
  });
  if (!cs.ok || !cs.data?.id || !cs.data?.url) {
    console.error('Stripe session create failed', cs.status, cs.data);
    const detail = (cs.data && cs.data.error && (cs.data.error.message || cs.data.error.type)) || JSON.stringify(cs.data).slice(0,200);
    return bad(`Stripe rejected checkout session (status ${cs.status}): ${detail}`, 500);
  }

  await supa(`/cnf_pending_signups?id=eq.${pendingId}`, {
    method: 'PATCH',
    body: JSON.stringify({ stripe_session_id: cs.data.id }),
  });

  return json(200, { url: cs.data.url, sessionId: cs.data.id });
};
