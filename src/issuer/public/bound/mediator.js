// The issuer side of browser-mediated sign-in (Flow A, polyfill form).
// Message handling lives in mediator-core.js; this file is the UI.

import { session, bindAuthForm, post, logout, describeGrant } from '/passkey.js';
import { guardButtons } from '/consent-guard.js';
import { isAllowedRpOrigin } from '/lib/origins.js';
import { listenForRequest } from '/bound/mediator-core.js';

const $ = (s) => document.querySelector(s);
const showOnly = (id) => ['waiting', 'fatal', 'auth', 'consent'].forEach((x) => $(`#${x}`).classList.toggle('hidden', x !== id));
const fatal = (msg) => { $('#fatal-msg').textContent = msg; showOnly('fatal'); };

let channel = null;
let request = null;

function respond(msg) {
  channel.respond(msg);
  window.close();
}

if (!window.opener) {
  fatal('This page is opened by sites that use Bound ID for sign-in. There is nothing to do here.');
} else {
  channel = listenForRequest({
    win: window, opener: window.opener, isAllowed: isAllowedRpOrigin,
    onRefused: fatal,
    onRequest: ({ rpOrigin, request: r }) => {
      request = r;
      document.querySelectorAll('.rp-origin').forEach((n) => { n.textContent = rpOrigin; });
      start(rpOrigin).catch((err) => fatal(err.message));
    },
  });
}

async function start(rpOrigin) {
  const user = await session();
  if (user) return consent(user, rpOrigin);
  showAuth(rpOrigin);
}

let authBound = false;
function showAuth(rpOrigin) {
  showOnly('auth');
  if (!authBound) { bindAuthForm($('#auth'), (u) => consent(u, rpOrigin)); authBound = true; }
}

let guard = null;
async function consent(user, rpOrigin) {
  $('#who').textContent = `${user.displayName} (@${user.username})`;
  $('#switch').onclick = async () => { guard?.dispose(); await logout().catch(() => {}); showAuth(rpOrigin); };
  const claims = request.claims.filter((c) => ['name', 'username'].includes(c));
  const asks = [`Know that it's you${claims.length ? ` (and see your ${claims.join(' and ')})` : ''}. It gets an ID unique to this site.`];
  let note = '';
  if (request.access) {
    try {
      const d = await post('/bound/describe', request.access);
      for (const g of d.grants) asks.push(describeGrant(g));
      note = `It can keep this access for up to ${d.renewHours} hours while you use it. You can revoke it at any time from your Bound ID account.`;
    } catch (e) { return respond({ error: e.code ?? 'invalid_request' }); }
  }
  $('#asks').replaceChildren(...asks.map((t) => Object.assign(document.createElement('li'), { textContent: t })));
  $('#duration').textContent = note;
  showOnly('consent');

  // Allow only works once this popup has been visible and focused for a moment.
  guard?.dispose();
  guard = guardButtons([$('#approve')]);
  $('#deny').onclick = () => respond({ error: 'access_denied' });
  $('#approve').onclick = async () => {
    if (!guard.armed) return;
    guard.dispose();
    $('#approve').disabled = true;
    try {
      const out = await post('/bound/authorize', {
        rp: rpOrigin, nonce: request.nonce, jkt: request.jkt, claims, access: request.access,
      });
      respond(out);
    } catch (e) {
      $('#consent-error').textContent = e.message;
      guard = guardButtons([$('#approve')]);
    }
  };
}
