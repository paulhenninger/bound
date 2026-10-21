// Client side: make requests that carry a Bound token and a fresh proof.
// Works in Node and in browsers.

import { utf8 } from './encoding.js';
import { createProof } from './proof.js';

// Latest server nonce seen per origin (servers send it in `Bound-Nonce`).
const nonces = new Map();

/**
 * fetch() wrapper. `holder` signs the proof; `token` (optional) goes in the
 * Authorization header. JSON bodies are serialised once so the bytes that are
 * hashed into the proof are exactly the bytes that are sent. If the server
 * demands a fresh nonce (`use_nonce`), the request is re-signed with it once.
 */
export async function boundFetch(holder, url, { method = 'GET', json, token, headers = {}, fetch: f = globalThis.fetch, credentials } = {}) {
  url = new URL(url, globalThis.location?.href).href;
  const origin = new URL(url).origin;
  const body = json === undefined ? undefined : utf8(JSON.stringify(json));
  let res, data;
  for (let attempt = 0; attempt < 2; attempt++) {
    const nonce = nonces.get(origin);
    const h = { ...headers, 'bound-proof': await createProof(holder, { method, url, token, body, nonce }) };
    if (token) h.authorization = `Bound ${token}`;
    if (body) h['content-type'] = 'application/json';
    res = await f(url, { method, headers: h, body, credentials });
    data = null;
    try { data = await res.json(); } catch { /* empty */ }
    const fresh = res.headers.get?.('bound-nonce');
    if (fresh) nonces.set(origin, fresh);
    if (!(res.status === 401 && data?.error === 'use_nonce' && fresh && fresh !== nonce)) break;
  }
  return { status: res.status, ok: res.ok, data, headers: res.headers };
}
