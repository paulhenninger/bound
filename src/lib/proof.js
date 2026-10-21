// Bound-Proof: a per-request proof of possession, sent in the `Bound-Proof`
// header on every request that uses a Bound token or a bound session.
//
//   proof = b64u(JSON payload) "." b64u(ES256 signature over the b64u payload)
//   payload = { typ:"bound-proof", jwk, htm, htu, iat, jti, bdy, ath?, nonce? }
//
// It is DPoP (RFC 9449) with two changes: the body is always covered (`bdy`),
// and there is no JOSE header to negotiate (the algorithm is fixed).

import { b64u, b64uJson, unb64uJson, sha256b64u, randomId, utf8, timingSafeEqual, now as nowSec } from './encoding.js';
import { sign, verify, thumbprint, importPublicJwk } from './keys.js';

export const PROOF_MAX_AGE = 60;
export const MIN_JTI_LENGTH = 22;   // 128 bits of base64url

export class ProofError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, msg) => { throw new ProofError(code, msg); };

/** The canonical request target: absolute URL without fragment. */
export function htu(url) {
  const u = new URL(url);
  u.hash = '';
  return u.href;
}

const bodyHash = (body) => sha256b64u(body ?? new Uint8Array(0));

export async function createProof(holder, { method, url, token, body, nonce }) {
  const payload = {
    typ: 'bound-proof',
    jwk: holder.jwk,
    htm: method.toUpperCase(),
    htu: htu(url),
    iat: nowSec(),
    jti: randomId(),
    bdy: await bodyHash(body),
  };
  if (token) payload.ath = await sha256b64u(token);
  if (nonce) payload.nonce = nonce;
  const p = b64uJson(payload);
  return `${p}.${await sign(holder.privateKey, p)}`;
}

/**
 * Verify a proof against the request actually received.
 *   opts: { method, url, body, token?, replay (ReplayCache), nonces? (NonceIssuer), now? }
 * With `nonces`, the proof must carry a nonce the server issued recently
 * (code `use_nonce` otherwise), so a proof cannot be signed ahead of time.
 * Returns { jwk, jkt, payload }. The caller MUST then check that `jkt` is the
 * key it expects (token holder, or session key).
 */
export async function verifyProof(proof, opts) {
  if (typeof proof !== 'string' || proof.length > 4096) fail('invalid_proof', 'proof missing');
  const segs = proof.split('.');
  if (segs.length !== 2) fail('invalid_proof', 'malformed proof');
  let payload;
  try { payload = unb64uJson(segs[0]); } catch { fail('invalid_proof', 'malformed proof'); }
  if (payload?.typ !== 'bound-proof') fail('invalid_proof', 'wrong proof type');

  let key;
  try { key = await importPublicJwk(payload.jwk); } catch { fail('invalid_proof', 'bad proof key'); }
  if (!(await verify(key, segs[1], segs[0]))) fail('invalid_proof', 'bad proof signature');

  const t = opts.now ?? nowSec();
  if (!Number.isInteger(payload.iat) || Math.abs(t - payload.iat) > PROOF_MAX_AGE) fail('invalid_proof', 'proof stale');
  if (payload.htm !== opts.method.toUpperCase()) fail('invalid_proof', 'method mismatch');
  if (payload.htu !== htu(opts.url)) fail('invalid_proof', 'url mismatch');
  if (payload.bdy !== await bodyHash(opts.body)) fail('invalid_proof', 'body mismatch');
  if (opts.token) {
    if (payload.ath !== await sha256b64u(opts.token)) fail('invalid_proof', 'token mismatch');
  } else if (payload.ath) {
    fail('invalid_proof', 'unexpected ath');
  }
  if (typeof payload.jti !== 'string' || payload.jti.length < MIN_JTI_LENGTH || payload.jti.length > 128) fail('invalid_proof', 'bad jti');
  if (opts.nonces && !(await opts.nonces.valid(payload.nonce, t))) fail('use_nonce', 'proof must carry a fresh server nonce');
  if (!opts.replay.add(payload.jti, payload.iat + PROOF_MAX_AGE * 2)) fail('replayed', 'proof replayed');

  return { jwk: payload.jwk, jkt: await thumbprint(payload.jwk), payload };
}

/**
 * Remembers proof jtis until they could no longer pass the freshness check.
 * Expired entries are swept at most once a second. When full of live
 * entries it fails closed (refuses new proofs) rather than forgetting any.
 */
export class ReplayCache {
  #seen = new Map();
  #lastSweep = 0;
  constructor({ max = 200000 } = {}) { this.max = max; }
  add(jti, expiresAt) {
    const t = nowSec();
    if (this.#seen.size >= this.max && t !== this.#lastSweep) {
      this.#lastSweep = t;
      for (const [k, e] of this.#seen) if (e < t) this.#seen.delete(k);
    }
    if (this.#seen.has(jti)) return false;
    if (this.#seen.size >= this.max) fail('busy', 'replay cache full, try again later');
    this.#seen.set(jti, expiresAt);
    return true;
  }
}

/**
 * Server-supplied proof nonces (stateless). A nonce names a time window and is
 * MACed with a server secret; the current and previous windows are accepted.
 * A proof that must carry one cannot be signed before the server issued it,
 * which bounds what script that briefly controls a page can sign in advance.
 */
export class NonceIssuer {
  // A promise, created synchronously, so concurrent first calls share one key.
  #key = crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  constructor({ window = 30 } = {}) { this.window = window; }
  async #mac(w) {
    return b64u(new Uint8Array(await crypto.subtle.sign('HMAC', await this.#key, utf8(String(w)))).subarray(0, 16));
  }
  async current(t = nowSec()) {
    const w = Math.floor(t / this.window);
    return `${w}.${await this.#mac(w)}`;
  }
  async valid(nonce, t = nowSec()) {
    if (typeof nonce !== 'string' || nonce.length > 64) return false;
    const [ws, mac] = nonce.split('.');
    const w = Number(ws), cur = Math.floor(t / this.window);
    if (!Number.isInteger(w) || String(w) !== ws || (w !== cur && w !== cur - 1)) return false;
    return timingSafeEqual(mac ?? '', await this.#mac(w));
  }
}
