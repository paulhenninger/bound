import { loadAgentKey, resetAgentKey, openMediator, requestTokens } from '/lib/agent.js';
import { boundFetch } from '/lib/client.js';
import { attenuate } from '/lib/token.js';

const $ = (s) => document.querySelector(s);
const cfg = await (await fetch('/bound/config')).json();
let key = await loadAgentKey();   // non-extractable; lives in IndexedDB
const ROOT_KEY = 'bound.root-access';

// Sign-in only works at the exact origin the issuer will see and the server signs proofs for.
if (location.origin !== cfg.origin) {
  $('#wrong-host').textContent = `Open Notebook at ${cfg.origin} instead. Sign-in is bound to that exact address.`;
  $('#wrong-host').classList.remove('hidden');
}

// Every call to our own API carries the cookie *and* a proof from the session key.
const api = (path, opts = {}) => boundFetch(key, path, { ...opts, credentials: 'same-origin' });

const store = {
  get: () => { try { return localStorage.getItem(ROOT_KEY); } catch { return null; } },
  // Safe to keep in storage: it is useless without the non-extractable key.
  set: (t) => { try { t ? localStorage.setItem(ROOT_KEY, t) : localStorage.removeItem(ROOT_KEY); } catch { /* private mode */ } },
};

/** Hand the server a copy of our access token, bound to the server's key. */
const delegate = (root) => attenuate(root, key, { to: cfg.serverKey });

/** Renew our root token at the issuer, then re-delegate it to the server. */
async function renewAndRedelegate() {
  const root = store.get();
  if (!root) throw new Error('Notes access has ended. Sign out and sign in again.');
  const r = await boundFetch(key, `${cfg.issuer}/bound/renew`, { method: 'POST', token: root });
  if (!r.ok) {
    store.set(null);
    throw new Error(r.data?.error === 'grant_revoked' ? 'You revoked Notebook\'s access to your notes.' : `Access could not be renewed (${r.data?.error ?? r.status}). Sign in again.`);
  }
  store.set(r.data.access);
  const put = await api('/api/access', { method: 'PUT', json: { access: await delegate(r.data.access) } });
  if (!put.ok) throw new Error(put.data?.error ?? 'could not update access');
}

/** API call that transparently renews delegated access once. */
async function notesApi(path, opts) {
  let r = await api(path, opts);
  if (r.status === 401 && r.data?.error === 'access_expired') {
    await renewAndRedelegate();
    r = await api(path, opts);
  }
  if (r.status === 401 && ['no_session', 'invalid_proof'].includes(r.data?.error)) {
    // The session ended (idle, expired, or signed out elsewhere): back to sign-in.
    await refresh();
    $('#signin-error').textContent = 'Your session ended. Sign in again.';
    throw new Error('Your session ended. Sign in again.');
  }
  if (!r.ok) throw new Error(r.data?.error_description ?? r.data?.error ?? `HTTP ${r.status}`);
  return r.data;
}

/** What to tell the user when sign-in fails, by error code. */
const SIGNIN_ERRORS = {
  cancelled: 'Sign-in was cancelled.',
  access_denied: 'Sign-in was cancelled.',
  'timed out': 'Sign-in timed out. Try again.',
  invalid_nonce: 'Sign-in took too long. Try again.',
  expired: 'Sign-in took too long. Try again.',
  invalid_audience: "Notebook asked Bound ID for access it doesn't recognise. This is a bug in Notebook.",
  invalid_grants: "Notebook asked Bound ID for access it doesn't recognise. This is a bug in Notebook.",
  too_many_grants: 'You have too many active grants. Revoke some at your Bound ID account, then try again.',
  rate_limited: 'Too many attempts. Wait a minute and try again.',
  busy: 'The service is busy. Try again in a minute.',
};

// ---- sign-in -------------------------------------------------------------
async function signIn(withNotes, errorEl) {
  errorEl.textContent = '';
  let popup;
  try { popup = openMediator(cfg.issuer); } catch (e) { errorEl.textContent = e.message; return; }
  try {
    const n = await fetch('/bound/nonce', { method: 'POST' });
    if (!n.ok) throw new Error('Notebook is busy; try again.');
    const { nonce } = await n.json();
    const access = withNotes
      ? { aud: [cfg.rs], grants: [{ res: `${cfg.rs}/notes/`, act: ['read', 'write'] }] }
      : undefined;
    const tokens = await requestTokens(popup, cfg.issuer, { nonce, jkt: key.jkt, claims: ['name'], access });
    store.set(tokens.access ?? null);
    const r = await boundFetch(key, '/bound/session', {
      method: 'POST', token: tokens.identity,
      json: { access: tokens.access ? await delegate(tokens.access) : undefined },
    });
    if (!r.ok) throw new Error(r.data?.error ?? `HTTP ${r.status}`);
    await refresh();
  } catch (e) {
    if (!popup.closed) popup.close();
    errorEl.textContent = SIGNIN_ERRORS[e.message] ?? `Sign-in failed (${e.message}).`;
  }
}
// Both must open the popup synchronously in the click (popup blockers).
$('#signin').onclick = () => signIn($('#want-notes').checked, $('#signin-error'));
$('#connect').onclick = () => signIn(true, $('#connect-error'));

// Signing out ends the session, gives the access back (revokes the grant at the
// issuer), and throws the key away, so the next person on this browser gets a
// fresh, unlinkable key.
$('#signout').onclick = async () => {
  const root = store.get();
  if (root) await boundFetch(key, `${cfg.issuer}/bound/revoke`, { method: 'POST', token: root }).catch(() => {});
  await api('/api/logout', { method: 'POST' }).catch(() => {});
  store.set(null);
  await resetAgentKey();
  key = await loadAgentKey();
  refresh();
};

// A thief with the cookie but not the key: same request, no proof.
$('#steal').onclick = async () => {
  const r = await fetch('/api/me', { credentials: 'same-origin' });
  const d = await r.json();
  $('#steal-out').className = 'small ' + (r.ok ? 'err' : 'ok');
  $('#steal-out').textContent = r.ok ? 'Accepted (this should not happen)' : `Refused: HTTP ${r.status} ${d.error}. The cookie alone is worthless.`;
};

// ---- notes ---------------------------------------------------------------
async function loadNotes() {
  try {
    const { notes } = await notesApi('/api/notes');
    $('#notes').replaceChildren(...(notes.length ? notes.map(noteItem) : [Object.assign(document.createElement('li'), { className: 'muted small', textContent: 'No notes yet.' })]));
    $('#notes-error').textContent = '';
  } catch (e) { $('#notes-error').textContent = e.message; }
}
function noteItem(n) {
  const li = document.createElement('li');
  const t = document.createElement('span'); t.textContent = n.text;
  const del = Object.assign(document.createElement('button'), { className: 'link', textContent: 'Delete' });
  del.onclick = async () => {
    try { await notesApi(`/api/notes/${encodeURIComponent(n.id)}`, { method: 'DELETE' }); loadNotes(); }
    catch (e) { $('#notes-error').textContent = e.message; }
  };
  li.append(t, del);
  return li;
}
$('#add').onsubmit = async (e) => {
  e.preventDefault();
  const text = $('#text').value.trim();
  if (!text) return;
  try { await notesApi('/api/notes', { method: 'POST', json: { text } }); $('#text').value = ''; loadNotes(); }
  catch (err) { $('#notes-error').textContent = err.message; }
};

$('#atten').onclick = async () => {
  const out = $('#atten-out');
  try {
    const d = await notesApi('/api/attenuation-demo', { method: 'POST' });
    const rows = d.attempts.map((a) => `<tr><td>${esc(a.what)}</td><td class="${a.status < 300 ? 'ok' : 'err'}">${esc(a.status)}</td><td>${esc(a.result)}</td></tr>`).join('');
    out.innerHTML = `<table><tr><th>Attempt</th><th>Status</th><th>Result</th></tr>${rows}</table>
      <details class="mt"><summary class="small muted">Token blocks</summary><pre>${esc(JSON.stringify(d.blocks, null, 2))}</pre></details>`;
  } catch (e) { out.innerHTML = `<p class="err small">${esc(e.message)}</p>`; }
};
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// ---- page state ----------------------------------------------------------
async function refresh() {
  const r = await api('/api/me');
  const user = r.ok ? r.data : null;
  $('#signed-out').classList.toggle('hidden', !!user);
  $('#signed-in').classList.toggle('hidden', !user);
  if (!user) return;
  $('#name').textContent = typeof user.user.name === 'string' ? user.user.name : 'there';
  $('#sub').textContent = user.user.sub;
  $('#jkt').textContent = user.sessionKey;
  $('#notes-panel').classList.toggle('hidden', !user.access);
  $('#atten-panel').classList.toggle('hidden', !user.access);
  $('#connect-panel').classList.toggle('hidden', !!user.access);
  if (user.access) loadNotes();
}
refresh();
