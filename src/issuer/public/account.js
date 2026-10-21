import { session, bindAuthForm, api, post, logout, describeGrant } from '/passkey.js';

const $ = (s) => document.querySelector(s);

// Passkeys and the session are tied to the issuer's exact origin.
fetch('/.well-known/bound-issuer').then((r) => r.json()).then((md) => {
  if (md.issuer !== location.origin) {
    $('#wrong-host').textContent = `This issuer lives at ${md.issuer}. Open it there; passkeys made here won't work.`;
    $('#wrong-host').classList.remove('hidden');
  }
}).catch(() => {});

function grantItem(g, user) {
  const li = document.createElement('li');
  const head = document.createElement('div');
  if (g.verified) {
    // A site: its origin was verified by the browser when it asked.
    head.append(Object.assign(document.createElement('span'), { className: 'origin', textContent: g.client }));
  } else {
    // A device named itself; say so.
    head.append(Object.assign(document.createElement('span'), { className: 'unverified', textContent: `"${g.client}"` }),
      Object.assign(document.createElement('span'), { className: 'tag', textContent: 'device, name not verified' }));
  }
  const what = document.createElement('div'); what.className = 'small';
  what.textContent = g.grants.map(describeGrant).join('; ');
  const when = document.createElement('div'); when.className = 'muted small';
  when.textContent = `Granted ${new Date(g.created * 1000).toLocaleString()} · renewable until ${new Date(g.rex * 1000).toLocaleString()}`;
  const btn = Object.assign(document.createElement('button'), { className: 'revoke', textContent: 'Revoke' });
  const err = Object.assign(document.createElement('p'), { className: 'err small' });
  btn.onclick = async () => {
    // Two steps: the first click asks, the second revokes.
    if (!btn.dataset.confirm) {
      btn.dataset.confirm = '1';
      btn.textContent = 'Click again to revoke';
      setTimeout(() => { delete btn.dataset.confirm; btn.textContent = 'Revoke'; }, 4000);
      return;
    }
    btn.disabled = true;
    try { await post(`/api/grants/${encodeURIComponent(g.gid)}/revoke`); show(user); }
    catch (e) { err.textContent = `Could not revoke: ${e.message}`; btn.disabled = false; }
  };
  li.append(head, what, when, btn, err);
  return li;
}

async function show(user) {
  $('#auth').classList.toggle('hidden', !!user);
  $('#account').classList.toggle('hidden', !user);
  if (!user) return;
  $('#who').textContent = `${user.displayName} (@${user.username})`;
  const ul = $('#grants');
  try {
    const { grants } = await api('/api/grants');
    ul.replaceChildren(...(grants.length ? grants.map((g) => grantItem(g, user))
      : [Object.assign(document.createElement('li'), { className: 'muted small', textContent: 'None yet.' })]));
  } catch (e) {
    if (e.status === 401) return show(null);
    ul.replaceChildren(Object.assign(document.createElement('li'), { className: 'err small', textContent: `Could not load grants: ${e.message}` }));
  }
}

bindAuthForm($('#auth'), show);
$('#logout').onclick = async () => { await logout().catch(() => {}); show(null); };
show(await session());
