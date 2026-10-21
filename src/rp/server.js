// Demo relying party ("Notebook"): signs users in with Bound, keeps a session
// bound to the browser's key, and calls the Notes API with a token the browser
// delegated to this server.

import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as cfg from '../config.js';
import { createServer, listen, HttpError, cookie } from '../lib/http.js';
import { randomId, now } from '../lib/encoding.js';
import { makeHolder } from '../lib/keys.js';
import { verifyToken, parseToken, attenuate } from '../lib/token.js';
import { verifyProof, ReplayCache, NonceIssuer } from '../lib/proof.js';
import { authenticate, IssuerDirectory, AuthError } from '../lib/verifier.js';
import { boundFetch } from '../lib/client.js';
import { ExpiringMap } from '../lib/state.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = join(here, '..', '..');

const SESSION_TTL = 8 * 3600;     // absolute session lifetime
const SESSION_IDLE = 3600;        // a session ends after this long without a request

export async function createRelyingParty(opts = {}) {
  const origin = opts.origin ?? cfg.RP;
  const issuer = opts.issuer ?? cfg.ISSUER;
  const rsOrigin = opts.rs ?? cfg.RS;
  const directory = opts.directory ?? new IssuerDirectory(issuer);
  const replay = new ReplayCache();
  const serverKey = await makeHolder();   // this server's own non-exportable key
  const loginNonces = new ExpiringMap({ max: opts.maxNonces ?? 10000 });     // sign-in nonce -> true
  const sessions = new ExpiringMap({ max: opts.maxSessions ?? 100000 });     // sid -> { sub, claims, jkt, access, expires }
  const proofNonces = new NonceIssuer();  // server nonces for session proofs (SPEC §9)

  // ---- bound session -----------------------------------------------------
  // A session is a cookie *and* a key: every request must carry a proof
  // signed by the browser key the session was created for, over a nonce this
  // server issued moments ago, so proofs can't be signed ahead of time.
  async function requireSession(ctx) {
    const o = ctx.headers.origin;
    if (o ? o !== origin : ctx.method !== 'GET') throw new HttpError(403, 'bad_origin');
    const sid = ctx.cookies.rp_sid;
    const s = typeof sid === 'string' ? sessions.get(sid) : undefined;
    if (!s) throw new HttpError(401, 'no_session');
    let proof;
    try {
      proof = await verifyProof(ctx.headers['bound-proof'], { method: ctx.method, url: ctx.fullUrl, body: ctx.body, replay, nonces: proofNonces });
    } catch (e) { throw new HttpError(401, e.code === 'use_nonce' ? 'use_nonce' : 'invalid_proof', e.message); }
    if (proof.jkt !== s.jkt) throw new HttpError(401, 'invalid_proof', 'session is bound to a different key');
    // Sliding idle timeout, capped by the absolute lifetime.
    sessions.set(sid, s, Math.min(s.expires, now() + SESSION_IDLE));
    return s;
  }

  /** Check a delegated access token: issued for our user's key, now held by us. */
  async function checkDelegatedAccess(access, sessionJkt) {
    let t;
    try {
      t = await verifyToken(access, { issuerKey: directory.key, issuer, audience: rsOrigin });
    } catch (e) {
      if (e.code === 'issuer_unavailable') throw new HttpError(503, e.code, e.message);
      throw new HttpError(400, 'invalid_access', e.message);
    }
    if (parseToken(access)[0].payload.cnf.jkt !== sessionJkt) throw new HttpError(400, 'invalid_access', 'access token belongs to another key');
    if (t.holder !== serverKey.jkt) throw new HttpError(400, 'invalid_access', 'access token not delegated to this server');
    return access;
  }

  /** Call the Notes API with the delegated token, signing with our own key. */
  async function callNotes(s, method, path, json) {
    if (!s.access) throw new HttpError(403, 'no_access', 'notes access was not granted');
    let r;
    try { r = await boundFetch(serverKey, rsOrigin + path, { method, json, token: s.access }); }
    catch { throw new HttpError(502, 'rs_unavailable', 'the Notes API could not be reached'); }
    if (r.status === 401 && r.data?.error === 'expired') throw new HttpError(401, 'access_expired', 'delegated access expired; renew and re-delegate');
    if (!r.ok) throw new HttpError(r.status, r.data?.error ?? 'rs_error', r.data?.error_description);
    return r.data;
  }

  const routes = [
    ['GET /bound/config', () => ({ origin, issuer, rs: rsOrigin, serverKey: serverKey.jwk })],
    ['POST /bound/nonce', () => {
      const nonce = randomId(24);
      loginNonces.set(nonce, true, now() + 300);
      return { nonce };
    }],

    // Exchange an identity token (+ proof by its holder) for a bound session.
    ['POST /bound/session', async (ctx) => {
      if (ctx.headers.origin !== origin) throw new HttpError(403, 'bad_origin');
      let auth;
      try {
        auth = await authenticate({
          headers: ctx.headers, method: ctx.method, url: ctx.fullUrl, body: ctx.body,
          issuer, issuerKey: directory.key, audience: origin, replay,
        });
      } catch (e) {
        if (e instanceof AuthError) throw new HttpError(e.status, e.code, e.message);
        throw e;
      }
      const { token } = auth;
      if (token.blockCount !== 1 || token.root.grants.length) throw new HttpError(400, 'invalid_token', 'not an identity token');
      const fresh = typeof token.root.nonce === 'string' && loginNonces.take(token.root.nonce);
      if (!fresh) throw new HttpError(400, 'invalid_nonce');

      const { access } = ctx.json();
      const claims = token.root.claims && typeof token.root.claims === 'object' ? token.root.claims : {};
      const s = { sub: token.sub, claims, jkt: token.holder, created: now(), expires: now() + SESSION_TTL };
      if (access) s.access = await checkDelegatedAccess(access, s.jkt);
      const sid = randomId(32);
      sessions.set(sid, s, Math.min(s.expires, now() + SESSION_IDLE));
      ctx.res.setHeader('set-cookie', cookie(origin, 'rp_sid', sid, SESSION_TTL));
      return { user: { sub: s.sub, ...s.claims }, access: !!s.access };
    }],

    ['GET /api/me', async (ctx) => {
      const s = await requireSession(ctx);
      return { user: { sub: s.sub, ...s.claims }, access: !!s.access, sessionKey: s.jkt };
    }],
    ['PUT /api/access', async (ctx) => {
      const s = await requireSession(ctx);
      s.access = await checkDelegatedAccess(ctx.json().access, s.jkt);
      return { ok: true };
    }],
    ['GET /api/notes', async (ctx) => callNotes(await requireSession(ctx), 'GET', '/notes/')],
    ['POST /api/notes', async (ctx) => {
      const s = await requireSession(ctx);
      return callNotes(s, 'POST', '/notes/', { text: ctx.json().text });
    }],
    ['DELETE /api/notes/:id', async (ctx) => {
      const s = await requireSession(ctx);
      return callNotes(s, 'DELETE', `/notes/${encodeURIComponent(ctx.params.id)}`);
    }],

    // Show attenuation + delegation: hand a background worker a read-only,
    // 60-second token bound to the worker's own key, then try to misuse it.
    ['POST /api/attenuation-demo', async (ctx) => {
      const s = await requireSession(ctx);
      if (!s.access) throw new HttpError(403, 'no_access');
      const worker = await makeHolder();
      const sub = await attenuate(s.access, serverKey, {
        to: worker.jwk, ttl: 60, grants: [{ res: `${rsOrigin}/notes/`, act: ['read'] }],
      });
      const url = `${rsOrigin}/notes/`;
      const read = await boundFetch(worker, url, { token: sub });
      const write = await boundFetch(worker, url, { method: 'POST', token: sub, json: { text: 'worker was here' } });
      const thief = await boundFetch(serverKey, url, { token: sub });
      return {
        blocks: parseToken(sub).map((b, i) => ({
          i, signedBy: i === 0 ? 'issuer' : (b.payload.by ? 'previous holder' : '?'),
          ...Object.fromEntries(['sub', 'aud', 'exp', 'grants', 'cnf', 'gid'].filter((k) => k in b.payload).map((k) => [k, b.payload[k]])),
        })),
        attempts: [
          { what: 'worker reads notes with its token', status: read.status, result: read.ok ? `${read.data.notes.length} notes` : read.data?.error },
          { what: 'worker tries to write', status: write.status, result: write.data?.error ?? 'ok' },
          { what: 'this server tries to use the worker token', status: thief.status, result: thief.data?.error ?? 'ok' },
        ],
      };
    }],

    ['POST /api/logout', async (ctx) => {
      // Ending a session takes the session key, like everything else on it.
      // The cookie is cleared either way.
      const s = await requireSession(ctx).catch((e) => { if (e.code === 'use_nonce') throw e; return null; });
      if (s) sessions.delete(ctx.cookies.rp_sid);
      ctx.res.setHeader('set-cookie', cookie(origin, 'rp_sid', '', 0));
      return { ok: !!s };
    }],
  ];

  const server = createServer({
    origin, routes, nonces: proofNonces,
    staticDirs: { '/lib/': join(ROOT, 'src', 'lib'), '/': join(here, 'public') },
    headers: {
      'content-security-policy': `default-src 'self'; connect-src 'self' ${issuer}; frame-ancestors 'none'; base-uri 'none'`,
      'referrer-policy': 'no-referrer',
    },
  });
  return { server, origin, serverKey, sessions, listen: () => listen(server, cfg.port(origin)) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const rp = await createRelyingParty();
  await rp.listen();
  console.log(`rp       ${rp.origin}`);
}
