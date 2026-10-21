// Request authentication for resource servers and relying parties:
// verify the token, verify the proof, and check that they belong together.

import { verifyToken, TokenError } from './token.js';
import { verifyProof, ProofError } from './proof.js';
import { importPublicJwk } from './keys.js';

export class AuthError extends Error {
  constructor(code, message, status = 401) { super(message); this.code = code; this.status = status; }
}

/** The issuer's keys could not be fetched. Not the client's fault: 503. */
export class IssuerUnavailableError extends AuthError {
  constructor(message) { super('issuer_unavailable', message, 503); }
}

/** Fetches and caches an issuer's metadata and keys from /.well-known/bound-issuer. */
export class IssuerDirectory {
  #keys = new Map();
  #lastFetch = -Infinity;
  #lastFailure = -Infinity;
  #inflight = null;
  constructor(issuer, { fetch: f = globalThis.fetch, minInterval = 30_000, failureBackoff = 5_000 } = {}) {
    this.issuer = issuer;
    this.fetch = f;
    this.minInterval = minInterval;
    this.failureBackoff = failureBackoff;
  }
  async metadata() {
    const res = await this.fetch(new URL('/.well-known/bound-issuer', this.issuer), { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(`issuer metadata: HTTP ${res.status}`);
    const md = await res.json();
    if (md.issuer !== this.issuer) throw new Error('issuer metadata mismatch');
    if (!Array.isArray(md.keys)) throw new Error('issuer metadata has no keys');
    return md;
  }
  async #load() {
    const md = await this.metadata();
    const keys = new Map();
    for (const jwk of md.keys) keys.set(jwk.kid, await importPublicJwk(jwk));
    this.#keys = keys;   // swap in whole: lookups never see a half-built set
  }
  #refresh() {
    // One fetch at a time; at most every 30 s once we have keys (so unknown kids
    // can't be used to hammer the issuer), and back off after a failure.
    if (this.#inflight) return this.#inflight;
    const t = Date.now();
    if (t - this.#lastFailure < this.failureBackoff) return Promise.reject(new IssuerUnavailableError('issuer keys unavailable'));
    if (this.#keys.size && t - this.#lastFetch < this.minInterval) return Promise.resolve();
    this.#lastFetch = t;
    this.#inflight = this.#load()
      .catch((e) => { this.#lastFailure = Date.now(); throw new IssuerUnavailableError(`issuer keys unavailable: ${e.message}`); })
      .finally(() => { this.#inflight = null; });
    return this.#inflight;
  }
  /** Key lookup for verifyToken(). Throws IssuerUnavailableError if the issuer can't be reached. */
  key = async (iss, kid) => {
    if (iss !== this.issuer) return null;
    if (!this.#keys.has(kid)) await this.#refresh();
    return this.#keys.get(kid) ?? null;
  };
}

/** Extract the token from `Authorization: Bound <token>`. */
export function tokenFromHeaders(headers) {
  const h = headers.authorization ?? '';
  const m = /^Bound ([A-Za-z0-9_~.-]+)$/.exec(h);
  return m ? m[1] : null;
}

/**
 * Authenticate a token-carrying request.
 *   { headers, method, url, body, issuer, issuerKey, audience, replay }
 * Returns { token, proof }. Throws AuthError.
 */
export async function authenticate(req) {
  // req.nonces (optional): require a server nonce in the proof (see NonceIssuer).
  const tokenStr = tokenFromHeaders(req.headers);
  if (!tokenStr) throw new AuthError('missing_token', 'Authorization: Bound token required');
  try {
    const token = await verifyToken(tokenStr, {
      issuerKey: req.issuerKey, issuer: req.issuer, audience: req.audience, now: req.now,
    });
    const proof = await verifyProof(req.headers['bound-proof'], {
      method: req.method, url: req.url, body: req.body, token: tokenStr, replay: req.replay, nonces: req.nonces, now: req.now,
    });
    if (proof.jkt !== token.holder) throw new AuthError('invalid_proof', 'proof key is not the token holder');
    return { token, proof, tokenStr };
  } catch (e) {
    if (e instanceof AuthError) throw e;
    if (e instanceof TokenError || e instanceof ProofError) throw new AuthError(e.code, e.message, e.code === 'busy' ? 503 : 401);
    throw e;
  }
}

export function wwwAuthenticate(err) {
  return `Bound error="${err.code ?? 'invalid_request'}", error_description="${String(err.message).replace(/"/g, "'")}"`;
}
