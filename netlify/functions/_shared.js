const crypto = require('crypto');

const SUPA_URL = process.env.SUPABASE_URL;
const SUPA_KEY = process.env.SUPABASE_SERVICE_KEY;
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY;

function json(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  };
}

function bad(message, code = 400) {
  return json(code, { error: message });
}

function parseBody(event) {
  if (!event.body) return {};
  try {
    const raw = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf8')
      : event.body;
    return JSON.parse(raw);
  } catch (e) {
    return {};
  }
}

// scrypt password hashing. Stored as "salt_hex:hash_hex".
function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(plain), salt, 32);
  return salt.toString('hex') + ':' + hash.toString('hex');
}

function verifyPassword(plain, stored) {
  if (!stored || typeof stored !== 'string' || !stored.includes(':')) return false;
  const [saltHex, hashHex] = stored.split(':');
  let saltBuf, hashBuf;
  try {
    saltBuf = Buffer.from(saltHex, 'hex');
    hashBuf = Buffer.from(hashHex, 'hex');
  } catch (e) {
    return false;
  }
  if (hashBuf.length === 0) return false;
  const candidate = crypto.scryptSync(String(plain), saltBuf, hashBuf.length);
  return crypto.timingSafeEqual(candidate, hashBuf);
}

function normalizeAnswer(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

// Thin wrapper over Supabase's PostgREST endpoint. Uses the service-role key,
// so it bypasses RLS — only call from server functions.
async function supa(path, init = {}) {
  const url = SUPA_URL.replace(/\/$/, '') + '/rest/v1' + path;
  const res = await fetch(url, {
    ...init,
    headers: {
      apikey: SUPA_KEY,
      Authorization: 'Bearer ' + SUPA_KEY,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
  let data = null;
  const text = await res.text();
  if (text) {
    try { data = JSON.parse(text); } catch (e) { data = text; }
  }
  return { ok: res.ok, status: res.status, data };
}

async function findAccount(username) {
  const u = String(username || '').trim();
  if (!u) return null;
  const res = await supa(
    `/cnf_accounts?username=eq.${encodeURIComponent(u)}&select=*`
  );
  if (!res.ok || !Array.isArray(res.data)) return null;
  return res.data[0] || null;
}

// Stripe REST. Recursively form-encodes nested objects (line_items, metadata, …).
async function stripe(path, params) {
  const method = params ? 'POST' : 'GET';
  const body = new URLSearchParams();
  function add(key, val) {
    if (val === null || val === undefined) return;
    if (Array.isArray(val)) {
      val.forEach((v, i) => add(`${key}[${i}]`, v));
    } else if (typeof val === 'object') {
      for (const [k, v] of Object.entries(val)) add(`${key}[${k}]`, v);
    } else {
      body.append(key, String(val));
    }
  }
  if (params) for (const [k, v] of Object.entries(params)) add(k, v);
  const res = await fetch('https://api.stripe.com/v1' + path, {
    method,
    headers: {
      Authorization: 'Bearer ' + STRIPE_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params ? body.toString() : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

function publicAccount(a) {
  if (!a) return null;
  return {
    username: a.username,
    isAdmin: !!a.is_admin,
    avatar: a.avatar_data || null,
    groupId: a.group_id || null,
  };
}

module.exports = {
  json, bad, parseBody,
  hashPassword, verifyPassword, normalizeAnswer,
  supa, findAccount, stripe, publicAccount,
};
