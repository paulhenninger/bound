// Bounded, self-expiring in-memory state for the demo servers. Anything an
// unauthenticated client can create (challenges, nonces, pending requests)
// lives here, so it can neither grow without limit nor outlive its use.

import { now } from './encoding.js';

export class CapacityError extends Error {
  constructor() { super('server is busy, try again later'); this.status = 503; this.code = 'busy'; }
}

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
