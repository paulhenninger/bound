// A simulated browser for end-to-end tests: a per-origin cookie jar, an Origin
// header on every non-GET request, and, for pages that keep a device-bound
// session (the issuer's), a per-origin key that signs a proof on every call,
// as the real pages do with boundFetch.

import { makeHolder } from '../../src/lib/keys.js';
import { boundFetch } from '../../src/lib/client.js';

export class Browser {
  constructor({ boundOrigins = [] } = {}) {
    this.jar = new Map();
    this.boundOrigins = new Set(boundOrigins);   // origins whose pages sign every call
    this.keys = new Map();                       // origin -> page key
  }

  /** fetch() as a page of `pageOrigin` would: cookies for the target, Origin on non-GET. */
  fetchAs(pageOrigin) {
    return async (url, init = {}) => {
      const target = new URL(url).origin;
      const headers = { ...(init.headers ?? {}) };
      if ((init.method ?? 'GET') !== 'GET') headers.origin = pageOrigin;
      const cookie = this.jar.get(target);
      if (cookie) headers.cookie = cookie;
      const res = await fetch(url, { ...init, headers });
      const set = res.headers.get('set-cookie');
      if (set) {
        const pair = set.split(';')[0];
        if (/Max-Age=0/i.test(set)) this.jar.delete(target); else this.jar.set(target, pair);
      }
      return res;
    };
  }

  /** The key a page of `origin` signs with (created on first use, like loadAgentKey). */
  async pageKey(origin) {
    if (!this.keys.has(origin)) this.keys.set(origin, await makeHolder());
    return this.keys.get(origin);
  }

  /** JSON call from a page of `pageOrigin`. Calls to bound origins carry a proof. */
  async json(pageOrigin, url, body, method = 'POST') {
    const target = new URL(url).origin;
    if (this.boundOrigins.has(target)) {
      const r = await boundFetch(await this.pageKey(target), url, {
        method, json: method === 'GET' ? undefined : body ?? {}, fetch: this.fetchAs(pageOrigin),
      });
      return { status: r.status, data: r.data };
    }
    const res = await this.fetchAs(pageOrigin)(url, { method, headers: { 'content-type': 'application/json' }, body: body && JSON.stringify(body) });
    return { status: res.status, data: await res.json().catch(() => null) };
  }
}
