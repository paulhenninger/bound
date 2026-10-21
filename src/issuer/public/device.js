// Interaction page for Flow B (back-channel requests from CLIs, TVs, agents).
import { session, bindAuthForm, post, describeGrant } from '/passkey.js';
import { guardButtons } from '/consent-guard.js';

const $ = (s) => document.querySelector(s);
const showOnly = (id) => ['auth', 'enter', 'decide', 'done'].forEach((x) => $(`#${x}`).classList.toggle('hidden', x !== id));

function enter(user) {
  $('#who').textContent = `${user.displayName} (@${user.username})`;
  showOnly('enter');
  $('#code').focus();
}

let guard = null;
$('#lookup').onclick = async () => {
  const user_code = $('#code').value;
  $('#enter-error').textContent = '';
  try {
    const r = await post('/bound/interaction/lookup', { user_code });
    $('#client').textContent = `"${r.client_name}"`;
    $('#asks').replaceChildren(...r.grants.map((g) => Object.assign(document.createElement('li'), { textContent: describeGrant(g) })));
    $('#duration').textContent = `It can keep this access for up to ${r.renewHours} hours. You can revoke it at any time from your account.`;
    const ago = Math.max(0, Math.round(Date.now() / 1000 - r.created));
    $('#when').textContent = `Requested ${ago < 120 ? `${ago} seconds` : `${Math.round(ago / 60)} minutes`} ago, from network address ${r.network}.`;
    $('#decide-error').textContent = '';
    showOnly('decide');
    guard?.dispose();
    guard = guardButtons([$('#approve')]);
    const decide = (approve) => async () => {
      if (approve && !guard.armed) return;
      $('#approve').disabled = $('#deny').disabled = true;
      try {
        await post('/bound/interaction/decide', { user_code, approve });
        guard.dispose();
        $('#done-msg').textContent = approve ? 'Approved. You can return to your device.' : 'Denied. The device gets nothing.';
        showOnly('done');
      } catch (e) {
        $('#decide-error').textContent = e.code === 'unknown_code' ? 'This request has expired. Start again on your device.' : e.message;
        $('#deny').disabled = false;
      }
    };
    $('#approve').onclick = decide(true);
    $('#deny').onclick = decide(false);
  } catch (e) { $('#enter-error').textContent = e.message; }
};

const user = await session();
if (user) enter(user); else { showOnly('auth'); bindAuthForm($('#auth'), enter); }
