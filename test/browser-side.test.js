// Flow A's browser-side checks, with fake windows: the mediator popup's
// message handling, the RP page's requestTokens(), and the consent-button guard.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { listenForRequest } from '../src/issuer/public/bound/mediator-core.js';
import { guardButtons } from '../src/issuer/public/consent-guard.js';
import { requestTokens } from '../src/lib/agent.js';
import { isAllowedRpOrigin } from '../src/lib/origins.js';

/** Minimal window: event listeners, controllable timers, recorded postMessage calls. */
class FakeWindow {
  constructor() { this.listeners = {}; this.timers = new Map(); this.nextId = 1; this.sent = []; this.closed = false; this.focused = true; }
  addEventListener(t, f) { (this.listeners[t] ??= new Set()).add(f); }
  removeEventListener(t, f) { this.listeners[t]?.delete(f); }
  emit(t, e = {}) { for (const f of [...(this.listeners[t] ?? [])]) f(e); }
  setInterval(f, ms) { const id = this.nextId++; this.timers.set(id, { f, ms, repeat: true }); return id; }
  setTimeout(f, ms) { const id = this.nextId++; this.timers.set(id, { f, ms, repeat: false }); return id; }
  clearInterval(id) { this.timers.delete(id); }
  clearTimeout(id) { this.timers.delete(id); }
  /** Run every pending timer once. */
  tick() { for (const [id, t] of [...this.timers]) { if (!t.repeat) this.timers.delete(id); t.f(); } }
  postMessage(data, targetOrigin) { this.sent.push({ data, targetOrigin }); }
  close() { this.closed = true; }
}

// ---- mediator popup ------------------------------------------------------------

function mediator() {
  const win = new FakeWindow(), opener = new FakeWindow();
  const got = [], refused = [];
  const ch = listenForRequest({ win, opener, isAllowed: isAllowedRpOrigin, onRequest: (r) => got.push(r), onRefused: (m) => refused.push(m) });
  const request = (origin, source = opener, data = { type: 'bound:request', nonce: 'n'.repeat(20), jkt: 'j' }) =>
    win.emit('message', { origin, source, data });
  return { win, opener, ch, got, refused, request };
}

test('mediator announces readiness without secrets, until a request arrives', () => {
  const { win, opener, request } = mediator();
  assert.deepEqual(opener.sent[0], { data: { type: 'bound:ready' }, targetOrigin: '*' });
  win.tick();
  assert.equal(opener.sent.length, 2);
  request('https://rp.example');
  win.tick();
  assert.equal(opener.sent.length, 2, 'pinging stops');
});

test('mediator takes the RP origin only from a message sent by its opener', () => {
  const { got, request } = mediator();
  request('https://evil.example', new FakeWindow());   // some other window
  request('https://evil.example', null);
  assert.equal(got.length, 0);
  request('https://rp.example');
  assert.equal(got.length, 1);
  assert.equal(got[0].rpOrigin, 'https://rp.example');
});

test('mediator handles one request only; later ones cannot change the RP', () => {
  const { got, request } = mediator();
  request('https://rp.example');
  request('https://other.example');
  assert.equal(got.length, 1);
  assert.equal(got[0].rpOrigin, 'https://rp.example');
});

test('mediator refuses opaque and plain-HTTP origins', () => {
  for (const o of ['null', 'http://rp.example', 'file://']) {
    const { got, refused, request } = mediator();
    request(o);
    assert.equal(got.length, 0, o);
    assert.equal(refused.length, 1, o);
  }
});

test('mediator delivers the response to the requesting origin only', () => {
  const { opener, ch, request } = mediator();
  assert.throws(() => ch.respond({ identity: 'x' }), 'nothing to answer yet');
  request('https://rp.example');
  ch.respond({ identity: 'tok' });
  assert.deepEqual(opener.sent.at(-1), { data: { type: 'bound:response', identity: 'tok' }, targetOrigin: 'https://rp.example' });
});

test('mediator ignores RP-supplied fields it should not trust', () => {
  const { got, request } = mediator();
  request('https://rp.example', undefined, { type: 'bound:request', nonce: 'n', jkt: 'j', rp: 'https://bank.example', claims: 'username', access: 'x' });
  assert.equal(got[0].rpOrigin, 'https://rp.example');
  assert.ok(!('rp' in got[0].request));
  assert.deepEqual(got[0].request.claims, []);
  assert.equal(got[0].request.access, undefined);
});

// ---- RP page: requestTokens ----------------------------------------------------

function rpPage() {
  const win = new FakeWindow(), popup = new FakeWindow();
  const p = requestTokens(popup, 'https://id.example', { nonce: 'n', jkt: 'j' }, { win, timeout: 50 });
  return { win, popup, p };
}

test('RP page answers only the issuer popup, and only to the issuer origin', async () => {
  const { win, popup, p } = rpPage();
  win.emit('message', { origin: 'https://evil.example', source: popup, data: { type: 'bound:ready' } });
  win.emit('message', { origin: 'https://id.example', source: new FakeWindow(), data: { type: 'bound:ready' } });
  assert.equal(popup.sent.length, 0);
  win.emit('message', { origin: 'https://id.example', source: popup, data: { type: 'bound:ready' } });
  assert.deepEqual(popup.sent[0], { data: { type: 'bound:request', nonce: 'n', jkt: 'j' }, targetOrigin: 'https://id.example' });
  // A forged response from elsewhere is ignored; the real one resolves.
  win.emit('message', { origin: 'https://evil.example', source: popup, data: { type: 'bound:response', identity: 'forged' } });
  win.emit('message', { origin: 'https://id.example', source: popup, data: { type: 'bound:response', identity: 'real' } });
  assert.deepEqual(await p, { identity: 'real', access: undefined });
});

test('RP page: issuer error rejects; a stuck popup times out and is closed', async () => {
  const a = rpPage();
  a.win.emit('message', { origin: 'https://id.example', source: a.popup, data: { type: 'bound:response', error: 'access_denied' } });
  await assert.rejects(a.p, /access_denied/);
  const b = rpPage();
  await assert.rejects(b.p, /timed out/);
  assert.ok(b.popup.closed);
});

// ---- consent button guard (clickjacking) ----------------------------------------

function guarded({ visible = true, focused = true } = {}) {
  const win = new FakeWindow();
  const doc = new FakeWindow();
  doc.visibilityState = visible ? 'visible' : 'hidden';
  doc.hasFocus = () => focused;
  const btn = { disabled: false };
  const g = guardButtons([btn], { win, doc, delay: 700 });
  return { win, doc, btn, g };
}

test('consent buttons start disabled and arm only after a delay', () => {
  const { win, btn, g } = guarded();
  assert.equal(btn.disabled, true);
  assert.equal(g.armed, false);
  win.tick();
  assert.equal(btn.disabled, false);
  assert.equal(g.armed, true);
});

test('consent buttons never arm while the popup is unfocused or hidden', () => {
  for (const s of [{ focused: false }, { visible: false }]) {
    const { win, btn } = guarded(s);
    win.tick();
    assert.equal(btn.disabled, true);
  }
});

test('losing focus disarms; regaining it re-arms only after the delay again', () => {
  const { win, doc, btn, g } = guarded();
  win.tick();
  win.emit('blur');
  assert.equal(btn.disabled, true);
  win.emit('focus');
  assert.equal(btn.disabled, true, 'not immediately');
  win.tick();
  assert.equal(btn.disabled, false);
  doc.visibilityState = 'hidden';
  doc.emit('visibilitychange');
  assert.equal(g.armed, false);
});
