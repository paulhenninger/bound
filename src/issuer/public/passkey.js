// Passkey ceremonies and API calls against the issuer.
//
// The issuer session is device-bound: every call carries a proof from a
// non-extractable key this page keeps in IndexedDB, so the session cookie on
// its own is worthless (SPEC §13).
import { b64u, unb64u } from '/lib/encoding.js';
import { boundFetch } from '/lib/client.js';
import { loadAgentKey, resetAgentKey } from '/lib/agent.js';

const KEY_NAME = 'issuer-session';
let key = loadAgentKey(KEY_NAME);

export async function api(path, { method = 'GET', json } = {}) {
  const r = await boundFetch(await key, path, { method, json, credentials: 'same-origin' });
  if (!r.ok) {
    throw Object.assign(new Error(r.data?.error_description || r.data?.error || `HTTP ${r.status}`), { code: r.data?.error, status: r.status });
  }
  return r.data;
}

export const post = (path, body) => api(path, { method: 'POST', json: body ?? {} });

export async function session() {
  try { return (await api('/api/session')).user; } catch { return null; }
}

/** Sign out, and start the next session with a new key. */
export async function logout() {
  try { await post('/api/logout'); } finally {
    await resetAgentKey(KEY_NAME);
    key = loadAgentKey(KEY_NAME);
  }
}

/** Run navigator.credentials.create() for server options and send the result back. */
async function createPasskey(o) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: unb64u(o.challenge), rp: o.rp,
      user: { id: unb64u(o.user.id), name: o.user.name, displayName: o.user.displayName },
      pubKeyCredParams: o.pubKeyCredParams, authenticatorSelection: o.authenticatorSelection,
      excludeCredentials: (o.excludeCredentials ?? []).map((c) => ({ type: c.type, id: unb64u(c.id) })),
      attestation: o.attestation, timeout: o.timeout,
    },
  });
  const r = cred.response;
  return (await post('/webauthn/register/verify', {
    challenge: o.challenge,
    credential: {
      id: cred.id, type: cred.type,
      response: {
        clientDataJSON: b64u(r.clientDataJSON),
        authenticatorData: b64u(r.getAuthenticatorData()),
        publicKey: b64u(r.getPublicKey()),
        publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
      },
    },
  })).user;
}

/** Create an account with a new passkey. */
export async function register(username, displayName) {
  return createPasskey(await post('/webauthn/register/options', { username, displayName }));
}

/** Add another passkey to the signed-in account (e.g. a second device). */
export async function addPasskey() {
  return createPasskey(await post('/webauthn/register/options', { add: true }));
}

export async function login() {
  const o = await post('/webauthn/login/options');
  const cred = await navigator.credentials.get({
    publicKey: { challenge: unb64u(o.challenge), rpId: o.rpId, userVerification: o.userVerification, timeout: o.timeout },
  });
  const r = cred.response;
  return (await post('/webauthn/login/verify', {
    challenge: o.challenge,
    credential: {
      id: cred.id, type: cred.type,
      response: {
        clientDataJSON: b64u(r.clientDataJSON),
        authenticatorData: b64u(r.authenticatorData),
        signature: b64u(r.signature),
        userHandle: r.userHandle ? b64u(r.userHandle) : null,
      },
    },
  })).user;
}

/** Wire up a sign-in / create-account form. Calls onUser(user) on success. */
export function bindAuthForm(root, onUser) {
  const $ = (s) => root.querySelector(s);
  const err = $('.auth-error');
  const run = (fn) => async () => {
    err.textContent = '';
    try { onUser(await fn()); } catch (e) {
      err.textContent = e.name === 'NotAllowedError' ? 'Passkey prompt was cancelled.' : e.message;
    }
  };
  $('.do-login').addEventListener('click', run(login));
  $('.do-register')?.addEventListener('click', run(() => {
    const u = $('.username').value.trim();
    if (!u) throw new Error('Choose a username first.');
    return register(u, $('.displayname').value.trim() || u);
  }));
}

/** One line per requested permission, saying what and how much. */
export const describeGrant = (g) => `${g.rs}, ${g.scope}: ${g.actions.join('; ')}`;
