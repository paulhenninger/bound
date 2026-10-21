// Browser-only helpers for relying-party pages: a persistent non-extractable
// key (the "agent key") and the sign-in exchange with the issuer's mediator.
//
// A browser that implements Bound natively would expose this as
// navigator.credentials.get({ bound: {...} }). This file is the polyfill: it
// uses a popup and postMessage, where the *browser* authenticates the origin of
// every message in both directions.

import { makeHolder } from './keys.js';

const DB = 'bound-agent';
const STORE = 'keys';

function idb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
const tx = async (mode, fn) => {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const req = fn(t.objectStore(STORE));
    t.oncomplete = () => resolve(req?.result);
    t.onerror = () => reject(t.error);
  });
};

/**
 * The agent key for this origin. Generated once, non-extractable: script on
 * this page can sign with it but nothing (including XSS) can copy it out.
 */
export async function loadAgentKey(name = 'session') {
  let kp = await tx('readonly', (s) => s.get(name));
  if (!kp) {
    kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    await tx('readwrite', (s) => s.put(kp, name));
  }
  return makeHolder(kp);
}

export async function resetAgentKey(name = 'session') {
  await tx('readwrite', (s) => s.delete(name));
}

/** Must be called synchronously inside a click handler (popup blockers). */
export function openMediator(issuer) {
  const w = 460, h = 640;
  const left = window.screenX + (window.outerWidth - w) / 2, top = window.screenY + 80;
  const popup = window.open(`${issuer}/bound/mediator.html`, 'bound-mediator', `popup,width=${w},height=${h},left=${left},top=${top}`);
  if (!popup) throw new Error('popup blocked');
  return popup;
}

/**
 * Run the sign-in exchange with an open mediator popup.
 *   request: { nonce, jkt, claims?, access?: { aud, grants } }
 * Resolves with { identity, access? } or rejects with the issuer's error.
 */
export function requestTokens(popup, issuer, request, { timeout = 10 * 60_000, win = globalThis.window } = {}) {
  const issuerOrigin = new URL(issuer).origin;
  return new Promise((resolve, reject) => {
    const timer = setInterval(() => { if (popup.closed) { cleanup(); reject(new Error('cancelled')); } }, 500);
    const deadline = setTimeout(() => { cleanup(); popup.close(); reject(new Error('timed out')); }, timeout);
    const window = win;
    function cleanup() { clearInterval(timer); clearTimeout(deadline); window.removeEventListener('message', onMessage); }
    function onMessage(e) {
      // The browser guarantees e.origin. Ignore anything not from the issuer's popup.
      if (e.origin !== issuerOrigin || e.source !== popup) return;
      const m = e.data;
      if (m?.type === 'bound:ready') {
        // targetOrigin pins delivery: if the popup was navigated elsewhere, nothing is sent.
        popup.postMessage({ type: 'bound:request', ...request }, issuerOrigin);
      } else if (m?.type === 'bound:response') {
        cleanup();
        if (m.error) reject(new Error(m.error)); else resolve({ identity: m.identity, access: m.access });
      }
    }
    window.addEventListener('message', onMessage);
  });
}
