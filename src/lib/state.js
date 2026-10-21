// Server-side state for the demo servers, designed so that anonymous clients
// can neither exhaust memory nor lock other users out:
//
//  - Sealer: state the server hands out (challenges, sign-in nonces) is sealed
//    with a MAC and an expiry instead of being stored, so issuing it costs no
//    memory. Only *using* it is recorded, after the expensive check succeeded.
//  - ExpiringMap: bounded, self-expiring storage for what must be stored.
//  - RateLimiter: per-source token buckets, so one client can't consume a
//    shared resource on everyone's behalf.

import { b64uJson, unb64uJson, b64u, utf8, randomId, timingSafeEqual, now } from './encoding.js';

export class CapacityError extends Error {
  constructor() { super('server is busy, try again later'); this.status = 503; this.code = 'busy'; }
}

export class RateLimitError extends Error {
  constructor(retryAfter = 1) {
    super('too many requests, slow down');
    this.status = 429; this.code = 'rate_limited';
    this.headers = { 'retry-after': String(Math.max(1, Math.ceil(retryAfter))) };
  }
}

/** Stateless, tamper-proof, expiring tokens for state the server hands out. */
export class Sealer {
  #key = crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  async #mac(body) {
    return b64u(new Uint8Array(await crypto.subtle.sign('HMAC', await this.#key, utf8(body))).subarray(0, 16));
  }
  /** Seal `data` for `ttl` seconds. Each sealed value has a unique `id` for single-use tracking. */
  async seal(data, ttl) {
    const body = b64uJson({ d: data, exp: now() + ttl, id: randomId() });
    return `${body}.${await this.#mac(body)}`;
  }
  /** { data, id, exp } for a genuine, unexpired value; otherwise null. */
  async open(sealed) {
    if (typeof sealed !== 'string' || sealed.length > 4096) return null;
    const parts = sealed.split('.');
    if (parts.length !== 2 || !timingSafeEqual(parts[1], await this.#mac(parts[0]))) return null;
    let v;
    try { v = unb64uJson(parts[0]); } catch { return null; }
    if (!Number.isInteger(v?.exp) || v.exp <= now() || typeof v.id !== 'string') return null;
    return { data: v.d, id: v.id, exp: v.exp };
  }
}

/**
 * Token buckets per key (usually the client's network address): `burst`
 * requests at once, refilled at `rate` per second. If the table of buckets is
 * full of active clients it lets new ones through (fails open): the limiter
 * exists to stop one source monopolising a resource, and must not itself
 * become a way to lock everyone out.
 */
export class RateLimiter {
  #buckets = new Map();   // key -> { tokens, t }
  #lastSweep = 0;
  constructor({ rate, burst, max = 100000 }) { this.rate = rate; this.burst = burst; this.max = max; }
  #level(b, t) { return Math.min(this.burst, b.tokens + (t - b.t) * this.rate); }
  /** Take `n` tokens for `key`. Throws RateLimitError when the bucket is empty. */
  take(key, n = 1) {
    const t = Date.now() / 1000;
    let b = this.#buckets.get(key);
    if (!b) {
      if (this.#buckets.size >= this.max) {
        if (t - this.#lastSweep >= 1) {   // at most once a second: sweeping is O(n)
          this.#lastSweep = t;
          for (const [k, x] of this.#buckets) if (this.#level(x, t) >= this.burst) this.#buckets.delete(k);
        }
        if (this.#buckets.size >= this.max) return;
      }
      b = { tokens: this.burst, t };
      this.#buckets.set(key, b);
    }
    b.tokens = this.#level(b, t);
    b.t = t;
    if (b.tokens < n) throw new RateLimitError((n - b.tokens) / this.rate);
    b.tokens -= n;
  }
}

/** The client's network address, as the rate limiters key on it. */
export const clientAddress = (ctx) => ctx.req.socket.remoteAddress ?? 'unknown';

export class ExpiringMap {
  #m = new Map();   // key -> { value, exp }
  #nextSweep = 0;
  constructor({ max = 10000 } = {}) { this.max = max; }

  get size() { return this.#m.size; }

  /** Store `value` until `exp` (seconds). Throws CapacityError when full of live entries. */
  set(key, value, exp) {
    this.#maybeSweep();
    if (!this.#m.has(key) && this.#m.size >= this.max) {
      this.sweep();
      if (this.#m.size >= this.max) throw new CapacityError();
    }
    this.#m.set(key, { value, exp });
    return value;
  }

  get(key) {
    const e = this.#m.get(key);
    if (!e) return undefined;
    if (e.exp <= now()) { this.#m.delete(key); return undefined; }
    return e.value;
  }

  has(key) { return this.get(key) !== undefined; }
  delete(key) { return this.#m.delete(key); }

  /** Remove and return a live value (single use). */
  take(key) {
    const v = this.get(key);
    this.#m.delete(key);
    return v;
  }

  *values() {
    const t = now();
    for (const { value, exp } of this.#m.values()) if (exp > t) yield value;
  }

  sweep() {
    const t = now();
    for (const [k, e] of this.#m) if (e.exp <= t) this.#m.delete(k);
    this.#nextSweep = t + 10;
  }

  #maybeSweep() { if (now() >= this.#nextSweep) this.sweep(); }
}
