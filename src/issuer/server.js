// Bound Issuer: authenticates users with passkeys and issues Bound tokens.
// Plays the roles OIDC splits between "OpenID Provider" and "Authorization Server".

import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as cfg from '../config.js';
import { createServer, listen, HttpError, cookie } from '../lib/http.js';
import { b64u, unb64u, utf8, fromUtf8, randomId, now } from '../lib/encoding.js';
import { exportPublicJwk, importKeyPairJwk } from '../lib/keys.js';
import { issueToken, parseToken, verifyToken } from '../lib/token.js';
import { verifyProof, ReplayCache, NonceIssuer } from '../lib/proof.js';
import { tokenFromHeaders, AuthError, wwwAuthenticate } from '../lib/verifier.js';
import { verifyRegistration, verifyAssertion, WebAuthnError } from '../lib/webauthn.js';
import { ExpiringMap, Sealer, RateLimiter, clientAddress } from '../lib/state.js';
import { isAllowedRpOrigin } from '../lib/origins.js';
import { loadStore, saver, pruneKeys } from './store.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = join(here, '..', '..');

const SESSION_TTL = 8 * 3600;
const CHALLENGE_TTL = 300;
const REQUEST_TTL = 600;
const CLAIMS = ['name', 'username'];
const LOOKUP_FAILURES = 5;          // failed user-code lookups allowed per session...
const LOOKUP_WINDOW = 60;           // ...per this many seconds
const SESSIONS_PER_USER = 10;       // oldest is ended when a user exceeds this
const GRANTS_PER_USER = 100;        // live grants; more must be revoked first
// Control, format (incl. bidi overrides) and unassigned code points: never in display text.
const UNSAFE_TEXT = /[\p{C}]/u;

/**
 * Per-address rate limits (requests per second, burst). Generous for people,
 * tight enough that one address can't monopolise a shared resource.
 */
export const DEFAULT_RATES = {
  http: { rate: 50, burst: 500 },          // every request
  signup: { rate: 1 / 60, burst: 5 },      // account creation attempts
  signin: { rate: 1 / 5, burst: 20 },      // passkey sign-in attempts
  device: { rate: 1 / 30, burst: 10 },     // new Flow B requests (so ≤ 30 pending per address)
};

/** Human description of what a grant's `res` covers, for consent screens. */
export function describeScope(res) {
  const u = new URL(res);
  if (u.pathname === '/') return `everything at ${u.origin}`;
  if (u.pathname.endsWith('/')) return `${u.pathname} and everything under it`;
  return `only ${u.pathname}`;
}

export async function createIssuer(opts = {}) {
  const origin = opts.origin ?? cfg.ISSUER;
  const rpId = new URL(origin).hostname;
  const dataFile = opts.dataFile ?? join(ROOT, 'data', 'issuer.json');
  const resourceServers = opts.resourceServers ?? cfg.RESOURCE_SERVERS;
  const ttl = { identity: opts.identityTtl ?? cfg.IDENTITY_TTL, access: opts.accessTtl ?? cfg.ACCESS_TTL, renew: opts.renewWindow ?? cfg.RENEW_WINDOW };
  const limits = { sessions: 100000, requests: 10000, usedChallenges: 100000, replay: 200000, ...opts.limits };
  const rates = { ...DEFAULT_RATES, ...opts.rates };

  // ---- persistent state --------------------------------------------------
  const { db, fresh, migrated } = await loadStore(dataFile);
  const save = saver(dataFile, db);
  const pruned = pruneKeys(db) | pruneGrants();
  if (fresh || migrated || pruned) await save();

  const keys = new Map();   // kid -> { publicKey, privateKey, jwk }
  for (const k of db.keys) {
    const kp = await importKeyPairJwk(k.key);
    keys.set(k.kid, { ...kp, jwk: { ...(await exportPublicJwk(kp.publicKey)), kid: k.kid, alg: 'ES256', use: 'sig' } });
  }
  const current = db.keys.at(-1);
  const signer = { iss: origin, kid: current.kid, privateKey: keys.get(current.kid).privateKey };
  const issuerKey = async (iss, kid) => (iss === origin ? keys.get(kid)?.publicKey ?? null : null);

  const hmacKey = await crypto.subtle.importKey('raw', utf8(db.pairwiseSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  /** Pairwise subject: the same user gets an unlinkable identifier at each audience. */
  const pairwiseSub = async (userId, audience) =>
    b64u(new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, utf8(`${userId}|${audience}`))).subarray(0, 16));

  /** Grants whose renewal window has closed are dead whether revoked or not: forget them. */
  function pruneGrants(t = now()) {
    let n = 0;
    for (const [gid, g] of Object.entries(db.grants)) if (g.rex < t) { delete db.grants[gid]; n++; }
    return n > 0;
  }

  // ---- ephemeral state ---------------------------------------------------
  // Nothing an anonymous client can trigger is stored before it has done real
  // work: challenges are sealed, not stored, and only recorded as used after a
  // successful passkey ceremony.
  const sealer = new Sealer();
  const usedChallenges = new ExpiringMap({ max: limits.usedChallenges });
  const sessions = new ExpiringMap({ max: limits.sessions });       // sid -> { userId, jkt, fails }
  const userSessions = new Map();                                    // userId -> [sid], oldest first
  const requests = new ExpiringMap({ max: limits.requests });       // request_id -> back-channel request
  const codes = new ExpiringMap({ max: limits.requests });          // normalized user code -> request_id
  // Two replay caches: Flow B accepts proofs from any key, so anonymous clients
  // must not be able to fill the cache that sessions and renewal depend on.
  const replay = new ReplayCache({ max: limits.replay });
  const anonReplay = new ReplayCache({ max: limits.replay });
  const nonces = new NonceIssuer();
  const limit = Object.fromEntries(Object.entries(rates).filter(([k, r]) => k !== 'http' && r).map(([k, r]) => [k, new RateLimiter(r)]));
  const throttle = (name, ctx) => limit[name]?.take(clientAddress(ctx));

  // A challenge is a sealed { kind, ... }, wrapped in base64url because that's
  // what WebAuthn hands back to us in clientDataJSON.
  const newChallenge = async (data) => b64u(utf8(await sealer.seal(data, CHALLENGE_TTL)));
  async function openChallenge(c, kind) {
    let sealed;
    try { sealed = fromUtf8(unb64u(c)); } catch { sealed = null; }
    const ch = await sealer.open(sealed);
    if (!ch || ch.data?.kind !== kind || usedChallenges.has(ch.id)) throw new HttpError(400, 'invalid_challenge');
    return ch;
  }
  /** Record a challenge as used. Call only after everything else succeeded. */
  function spendChallenge(ch) {
    if (usedChallenges.has(ch.id)) throw new HttpError(400, 'invalid_challenge');
    usedChallenges.set(ch.id, true, ch.exp);
  }

  // ---- device-bound issuer session ---------------------------------------
  // Like an RP's bound session (SPEC §9, §13): the cookie only counts together
  // with a proof, carrying a fresh server nonce, from the key the session was
  // created with. Issuer pages sign with a non-extractable key of their own.
  async function sessionProof(ctx) {
    try {
      return await verifyProof(ctx.headers['bound-proof'], { method: ctx.method, url: ctx.fullUrl, body: ctx.body, replay, nonces });
    } catch (e) {
      if (e.code === 'busy') throw new HttpError(503, 'busy', e.message);
      throw new HttpError(401, e.code === 'use_nonce' ? 'use_nonce' : 'invalid_proof', e.message);
    }
  }
  function startSession(ctx, userId, jkt) {
    const sid = randomId(32);
    sessions.set(sid, { userId, jkt, fails: [] }, now() + SESSION_TTL);
    // Each user has a bounded number of sessions; signing in again ends the oldest.
    const mine = (userSessions.get(userId) ?? []).filter((x) => sessions.has(x));
    mine.push(sid);
    while (mine.length > SESSIONS_PER_USER) sessions.delete(mine.shift());
    userSessions.set(userId, mine);
    ctx.res.setHeader('set-cookie', cookie(origin, 'bound_idp', sid, SESSION_TTL));
  }
  /** The signed-in user, or null. Throws if a session cookie comes without a valid proof. */
  const currentSession = async (ctx) => {
    const s = sessions.get(ctx.cookies.bound_idp);
    if (!s) return null;
    const proof = await sessionProof(ctx);
    if (proof.jkt !== s.jkt) throw new HttpError(401, 'invalid_proof', 'session is bound to a different key');
    const user = db.users[s.userId];
    return user ? { s, user } : null;
  };
  const checkOrigin = (ctx) => {
    if (ctx.headers.origin !== origin) throw new HttpError(403, 'bad_origin', 'cross-origin request refused');
  };
  /** Cookie-authenticated, state-changing calls must come from the issuer's own pages. */
  const requireSession = async (ctx) => {
    checkOrigin(ctx);
    const cur = await currentSession(ctx);
    if (!cur) throw new HttpError(401, 'login_required');
    return cur;
  };
  const requireUser = async (ctx) => (await requireSession(ctx)).user;
  const publicUser = (u) => ({
    id: u.id, username: u.username, displayName: u.displayName,
    passkeys: u.credentials.map((c) => ({ id: c.credentialId, created: c.created ?? u.created })),
  });

  // ---- input validation --------------------------------------------------
  function validateGrants(aud, grants) {
    if (!Array.isArray(aud) || aud.length !== 1 || typeof aud[0] !== 'string' || !Object.hasOwn(resourceServers, aud[0])) {
      throw new HttpError(400, 'invalid_audience', 'unknown resource server');
    }
    if (!Array.isArray(grants) || grants.length === 0 || grants.length > 16) throw new HttpError(400, 'invalid_grants');
    const rs = resourceServers[aud[0]];
    return grants.map((g) => {
      if (!g || typeof g !== 'object' || typeof g.res !== 'string') throw new HttpError(400, 'invalid_grants', 'res must be an absolute URL');
      let u; try { u = new URL(g.res); } catch { throw new HttpError(400, 'invalid_grants', 'res must be an absolute URL'); }
      if (u.origin !== aud[0]) throw new HttpError(400, 'invalid_grants', 'grant outside audience');
      if (u.username || u.password || u.search || u.hash || /%2f|%5c/i.test(u.pathname)) throw new HttpError(400, 'invalid_grants', 'res must be a plain path');
      if (!Array.isArray(g.act) || !g.act.length || g.act.some((a) => typeof a !== 'string' || !Object.hasOwn(rs.actions, a))) {
        throw new HttpError(400, 'invalid_grants', 'unknown action');
      }
      return { res: u.href, act: [...new Set(g.act)] };
    });
  }
  function validateAccess(access) {
    if (access === undefined || access === null) return null;
    if (typeof access !== 'object' || Array.isArray(access)) throw new HttpError(400, 'invalid_request', 'access must be an object');
    return { aud: access.aud, grants: validateGrants(access.aud, access.grants) };
  }
  function validateClaims(claims) {
    if (claims === undefined) return [];
    if (!Array.isArray(claims) || claims.some((c) => !CLAIMS.includes(c))) {
      throw new HttpError(400, 'invalid_request', `claims must be an array of: ${CLAIMS.join(', ')}`);
    }
    return [...new Set(claims)];
  }
  function cleanText(v, { field, max }) {
    if (typeof v !== 'string') throw new HttpError(400, 'invalid_request', `${field} must be a string`);
    const t = v.trim();
    if (!t || t.length > max || UNSAFE_TEXT.test(t)) throw new HttpError(400, 'invalid_request', `${field} must be 1-${max} printable characters`);
    return t;
  }

  // ---- grants & token minting --------------------------------------------
  async function recordGrant(user, { client, kind, aud, grants, jkt }) {
    // One live grant per (user, client, key). Re-approving the same access
    // extends it; approving different access replaces it, so an old, broader
    // grant can't linger behind a narrower new one.
    const t = now();
    pruneGrants(t);
    const scope = JSON.stringify([aud, grants]);
    let result = null;
    let live = 0;
    for (const g of Object.values(db.grants)) {
      if (g.revoked || g.userId !== user.id) continue;
      if (g.client !== client || g.jkt !== jkt) { live++; continue; }
      if (!result && JSON.stringify([g.aud, g.grants]) === scope) { g.rex = t + ttl.renew; result = g; live++; }
      else { g.revoked = true; g.revokedReason = 'superseded'; }
    }
    if (!result) {
      if (live >= GRANTS_PER_USER) throw new HttpError(409, 'too_many_grants', `you have ${live} active grants; revoke some at your Bound ID account first`);
      const gid = randomId(12);
      result = db.grants[gid] = { gid, userId: user.id, client, kind, aud, grants, jkt, created: t, rex: t + ttl.renew, revoked: false };
    }
    await save();
    return result;
  }

  async function mintAccess(user, grant) {
    return issueToken(signer, {
      sub: await pairwiseSub(user.id, grant.aud[0]),
      aud: grant.aud, cnf: { jkt: grant.jkt }, grants: grant.grants,
      gid: grant.gid, rex: grant.rex,
    }, { ttl: ttl.access });
  }

  const describe = (aud, grants) => grants.map((g) => ({
    res: g.res, rs: resourceServers[aud[0]]?.name, scope: describeScope(g.res),
    actions: g.act.map((a) => resourceServers[aud[0]]?.actions[a] ?? a),
  }));

  /**
   * Renewal and revocation by the token holder. Verifies a root access token
   * (accepting an expired one) and a proof by its holder; returns the grant.
   */
  async function holderGrant(ctx) {
    const tokenStr = tokenFromHeaders(ctx.headers);
    let token, proof;
    try {
      if (!tokenStr) throw new AuthError('missing_token', 'Authorization: Bound token required');
      // Expired tokens are accepted here, so evaluate the token as of its own
      // lifetime; the grant's renewal window (rex) bounds how late that can be.
      const root = parseToken(tokenStr)[0].payload;
      const at = Math.min(now(), (Number.isInteger(root.exp) ? root.exp : 0) - 1);
      token = await verifyToken(tokenStr, { issuerKey, issuer: origin, anyAudience: true, now: at });
      proof = await verifyProof(ctx.headers['bound-proof'], {
        method: ctx.method, url: ctx.fullUrl, body: ctx.body, token: tokenStr, replay,
      });
      if (proof.jkt !== token.holder) throw new AuthError('invalid_proof', 'proof key is not the token holder');
    } catch (e) {
      if (e.code === 'busy') throw new HttpError(503, 'busy', e.message);
      const err = e instanceof AuthError ? e : new AuthError(e.code ?? 'invalid_token', e.message);
      throw new HttpError(401, err.code, err.message, { 'www-authenticate': wwwAuthenticate(err) });
    }
    if (token.blockCount !== 1) throw new HttpError(400, 'not_renewable', 'only root tokens are renewable; ask your delegator');
    if (typeof token.root.gid !== 'string' || !token.root.grants.length) throw new HttpError(401, 'invalid_token', 'not an access token');
    const g = Object.hasOwn(db.grants, token.root.gid) ? db.grants[token.root.gid] : null;
    if (!g) throw new HttpError(401, 'renewal_window_closed', 'the grant has ended; authorize again');
    if (g.jkt !== token.holder) throw new HttpError(401, 'invalid_token', 'unknown grant');
    return g;
  }

  // ---- Flow B helpers ----------------------------------------------------
  const normalizeCode = (code) => String(code ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 32);
  function findByCode(s, code) {
    const t = now();
    s.fails = s.fails.filter((x) => x > t - LOOKUP_WINDOW);
    if (s.fails.length >= LOOKUP_FAILURES) throw new HttpError(429, 'slow_down', 'too many wrong codes; wait a minute');
    const id = codes.get(normalizeCode(code));
    const r = id && requests.get(id);
    if (!r || r.status !== 'pending') {
      s.fails.push(t);
      throw new HttpError(404, 'unknown_code', 'code not found or expired');
    }
    return r;
  }

  // ---- routes ------------------------------------------------------------
  const routes = [
    ['GET /.well-known/bound-issuer', () => ({
      issuer: origin, version: 1, alg: 'ES256', keys: [...keys.values()].map((k) => k.jwk),
      mediator: `${origin}/bound/mediator.html`,
      request_endpoint: `${origin}/bound/request`,
      token_endpoint: `${origin}/bound/token`,
      renew_endpoint: `${origin}/bound/renew`,
      revoke_endpoint: `${origin}/bound/revoke`,
      interaction: `${origin}/device.html`,
    })],

    // Passkey registration: creates an account, or (signed in) adds a passkey to it.
    ['POST /webauthn/register/options', async (ctx) => {
      const body = ctx.json();
      if (body.add === true) {
        const { user } = await requireSession(ctx);
        return creationOptions(await newChallenge({ kind: 'add', userId: user.id }), user.id, user.username, user.displayName,
          user.credentials.map((c) => c.credentialId));
      }
      const { username, displayName } = body;
      if (typeof username !== 'string' || !/^[a-z0-9._-]{2,32}$/i.test(username)) throw new HttpError(400, 'invalid_username');
      const name = displayName === undefined || displayName === '' ? username : cleanText(displayName, { field: 'displayName', max: 64 });
      if (Object.values(db.users).some((u) => u.username === username)) throw new HttpError(409, 'username_taken');
      const userId = randomId(16);
      return creationOptions(await newChallenge({ kind: 'register', username, displayName: name, userId }), userId, username, name, []);
    }],
    ['POST /webauthn/register/verify', async (ctx) => {
      checkOrigin(ctx);
      const { challenge, credential } = ctx.json();
      // Peek at the kind to apply the right limit before doing any real work.
      let kind = null;
      try { kind = JSON.parse(fromUtf8(unb64u(fromUtf8(unb64u(challenge)).split('.')[0]))).d?.kind; } catch { /* checked properly below */ }
      if (kind === 'add') return addPasskey(ctx, challenge, credential);
      throttle('signup', ctx);
      const ch = await openChallenge(challenge, 'register');
      const c = ch.data;
      const cred = await verifyRegistration({ credential, expectedChallenge: challenge, expectedOrigin: origin, rpId }).catch(passkeyError);
      // Checked again here: two sign-ups may have raced for the same name.
      if (Object.values(db.users).some((u) => u.username === c.username)) throw new HttpError(409, 'username_taken');
      if (credentialTaken(cred.credentialId)) throw new HttpError(409, 'credential_exists', 'this passkey is already registered');
      // The session proof is checked before the challenge is spent: if its nonce
      // went stale during a slow passkey prompt, the client can retry the same
      // ceremony with a fresh nonce.
      const proof = await sessionProof(ctx);
      spendChallenge(ch);
      db.users[c.userId] = { id: c.userId, username: c.username, displayName: c.displayName, credentials: [{ ...cred, created: now() }], created: now() };
      await save();
      startSession(ctx, c.userId, proof.jkt);
      return { user: publicUser(db.users[c.userId]) };
    }],

    // Passkey sign-in (discoverable credentials; no username needed).
    ['POST /webauthn/login/options', async () => ({ challenge: await newChallenge({ kind: 'login' }), rpId, userVerification: 'required', timeout: 120000 })],
    ['POST /webauthn/login/verify', async (ctx) => {
      checkOrigin(ctx);
      throttle('signin', ctx);
      const { challenge, credential } = ctx.json();
      const ch = await openChallenge(challenge, 'login');
      const user = Object.values(db.users).find((u) => u.credentials.some((c) => c.credentialId === credential?.id));
      if (!user) throw new HttpError(401, 'unknown_credential');
      const stored = user.credentials.find((c) => c.credentialId === credential.id);
      const { signCount } = await verifyAssertion({ credential, stored, expectedChallenge: challenge, expectedOrigin: origin, rpId }).catch(passkeyError);
      const proof = await sessionProof(ctx);   // before spending the challenge, as above
      spendChallenge(ch);
      // Most passkeys report a counter of 0; only write when it actually moved.
      if (signCount !== stored.signCount) { stored.signCount = signCount; await save(); }
      startSession(ctx, user.id, proof.jkt);
      return { user: publicUser(user) };
    }],

    ['GET /api/session', async (ctx) => {
      if (ctx.headers.origin && ctx.headers.origin !== origin) throw new HttpError(403, 'bad_origin');
      const cur = await currentSession(ctx);
      if (!cur) throw new HttpError(401, 'login_required');
      return { user: publicUser(cur.user) };
    }],
    ['POST /api/logout', async (ctx) => {
      checkOrigin(ctx);
      // Only the session's own key can end it; the cookie alone can't.
      const cur = await currentSession(ctx).catch((e) => { if (e.code === 'use_nonce') throw e; return null; });
      if (cur) sessions.delete(ctx.cookies.bound_idp);
      ctx.res.setHeader('set-cookie', cookie(origin, 'bound_idp', '', 0));
      return { ok: !!cur };
    }],
    ['POST /api/account/delete', async (ctx) => {
      const { user } = await requireSession(ctx);
      if (ctx.json().username !== user.username) throw new HttpError(400, 'invalid_request', 'type your username to confirm');
      for (const [gid, g] of Object.entries(db.grants)) if (g.userId === user.id) delete db.grants[gid];
      delete db.users[user.id];
      for (const sid of userSessions.get(user.id) ?? []) sessions.delete(sid);
      userSessions.delete(user.id);
      await save();
      ctx.res.setHeader('set-cookie', cookie(origin, 'bound_idp', '', 0));
      return { ok: true };
    }],
    ['POST /api/passkeys/:id/delete', async (ctx) => {
      const { user } = await requireSession(ctx);
      const i = user.credentials.findIndex((c) => c.credentialId === ctx.params.id);
      if (i < 0) throw new HttpError(404, 'not_found');
      if (user.credentials.length === 1) throw new HttpError(409, 'last_passkey', 'this is your only passkey; add another first, or delete the account');
      user.credentials.splice(i, 1);
      await save();
      return { user: publicUser(user) };
    }],
    ['GET /api/grants', async (ctx) => {
      if (ctx.headers.origin && ctx.headers.origin !== origin) throw new HttpError(403, 'bad_origin');
      const cur = await currentSession(ctx);
      if (!cur) throw new HttpError(401, 'login_required');
      const t = now();
      return { grants: Object.values(db.grants).filter((g) => g.userId === cur.user.id && !g.revoked && g.rex >= t)
        .map((g) => ({
          gid: g.gid, client: g.client, verified: g.kind === 'site', created: g.created, rex: g.rex,
          grants: describe(g.aud, g.grants),
        })) };
    }],
    ['POST /api/grants/:gid/revoke', async (ctx) => {
      const u = await requireUser(ctx);
      const g = Object.hasOwn(db.grants, ctx.params.gid) ? db.grants[ctx.params.gid] : null;
      if (!g || g.userId !== u.id) throw new HttpError(404, 'not_found');
      g.revoked = true;
      await save();
      return { ok: true };
    }],

    // Flow A: browser-mediated sign-in. Called only by the issuer's own mediator
    // page, which learned `rp` from the browser-authenticated postMessage origin.
    ['POST /bound/authorize', async (ctx) => {
      const user = await requireUser(ctx);
      const body = ctx.json();
      const { rp, nonce, jkt } = body;
      if (!isAllowedRpOrigin(rp)) throw new HttpError(400, 'invalid_request', 'rp must be an HTTPS origin (HTTP only on loopback)');
      if (typeof nonce !== 'string' || nonce.length < 16 || nonce.length > 128) throw new HttpError(400, 'invalid_nonce', 'nonce required');
      if (typeof jkt !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(jkt)) throw new HttpError(400, 'invalid_request', 'jkt required');
      const claims = validateClaims(body.claims);
      const access = validateAccess(body.access);
      const released = {};
      if (claims.includes('name')) released.name = user.displayName;
      if (claims.includes('username')) released.username = user.username;
      const identity = await issueToken(signer, {
        sub: await pairwiseSub(user.id, rp), aud: [rp], cnf: { jkt }, grants: [], nonce, claims: released,
      }, { ttl: ttl.identity });
      const out = { identity };
      if (access) {
        const grant = await recordGrant(user, { client: rp, kind: 'site', aud: access.aud, grants: access.grants, jkt });
        out.access = await mintAccess(user, grant);
      }
      return out;
    }],

    // Human-readable description of requested grants, for consent screens.
    ['POST /bound/describe', (ctx) => {
      const access = validateAccess(ctx.json());
      if (!access) throw new HttpError(400, 'invalid_request');
      return { grants: describe(access.aud, access.grants), renewHours: Math.round(ttl.renew / 3600) };
    }],

    // Flow B: back-channel authorization for clients without a browser.
    ['POST /bound/request', async (ctx) => {
      throttle('device', ctx);
      const proof = await checkProof(ctx);
      const body = ctx.json();
      const client_name = cleanText(body.client_name, { field: 'client_name', max: 64 });
      // A device names itself; it must not be able to pass that name off as a site address.
      if (/:\/\/|[/\\]/.test(client_name)) throw new HttpError(400, 'invalid_request', 'client_name must not look like an address');
      const clean = validateGrants(body.aud, body.grants);
      const request_id = randomId(24);
      let user_code;
      do user_code = randomUserCode(); while (codes.has(normalizeCode(user_code)));
      const exp = now() + REQUEST_TTL;
      requests.set(request_id, {
        request_id, user_code, client_name, aud: body.aud, grants: clean, jkt: proof.jkt, status: 'pending', created: now(),
        network: clientAddress(ctx),
      }, exp);
      codes.set(normalizeCode(user_code), request_id, exp);
      return { request_id, user_code, interact: `${origin}/device.html`, expires_in: REQUEST_TTL, interval: 2 };
    }],
    ['POST /bound/interaction/lookup', async (ctx) => {
      const { s } = await requireSession(ctx);
      const r = findByCode(s, ctx.json().user_code);
      return {
        client_name: r.client_name, created: r.created, network: r.network,
        grants: describe(r.aud, r.grants), renewHours: Math.round(ttl.renew / 3600),
      };
    }],
    ['POST /bound/interaction/decide', async (ctx) => {
      const { s, user } = await requireSession(ctx);
      const { user_code, approve } = ctx.json();
      const r = findByCode(s, user_code);
      if (approve === true) {
        r.grant = await recordGrant(user, { client: r.client_name, kind: 'device', aud: r.aud, grants: r.grants, jkt: r.jkt });
        r.userId = user.id;
        r.status = 'approved';
      } else r.status = 'denied';
      codes.delete(normalizeCode(user_code));
      return { ok: true };
    }],
    ['POST /bound/token', async (ctx) => {
      const proof = await checkProof(ctx);
      const { request_id } = ctx.json();
      const r = typeof request_id === 'string' ? requests.get(request_id) : undefined;
      // Only the key that made the request may collect the result.
      if (!r || r.jkt !== proof.jkt) throw new HttpError(400, 'invalid_request', 'unknown or expired request');
      if (r.status === 'pending') throw new HttpError(428, 'authorization_pending');
      requests.delete(r.request_id);
      if (r.status === 'denied') throw new HttpError(403, 'access_denied');
      // The user may have revoked the grant between approving and collection.
      const user = db.users[r.userId];
      if (!user || r.grant.revoked) throw new HttpError(403, 'access_denied', 'the grant was revoked');
      return { access: await mintAccess(user, r.grant) };
    }],

    // Renewal: replaces refresh tokens. The holder of a root access token signs
    // a renewal request; the issuer re-checks the grant and mints a fresh token.
    ['POST /bound/renew', async (ctx) => {
      const g = await holderGrant(ctx);
      if (g.revoked) throw new HttpError(401, 'grant_revoked');
      if (g.rex < now()) throw new HttpError(401, 'renewal_window_closed');
      const user = db.users[g.userId];
      if (!user) throw new HttpError(401, 'grant_revoked');
      return { access: await mintAccess(user, g) };
    }],

    // Revocation by the holder, e.g. when the user signs out of the client.
    // Revoking an already-revoked or ended grant succeeds: the outcome is the same.
    ['POST /bound/revoke', async (ctx) => {
      const g = await holderGrant(ctx).catch((e) => { if (e.code === 'renewal_window_closed') return null; throw e; });
      if (g && !g.revoked) { g.revoked = true; g.revokedReason = 'holder'; await save(); }
      return { ok: true };
    }],
  ];

  function creationOptions(challenge, userId, name, displayName, exclude) {
    return {
      challenge, rp: { id: rpId, name: 'Bound Demo Issuer' },
      user: { id: userId, name, displayName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      excludeCredentials: exclude.map((id) => ({ type: 'public-key', id })),
      attestation: 'none', timeout: 120000,
    };
  }

  const credentialTaken = (id) => Object.values(db.users).some((u) => u.credentials.some((x) => x.credentialId === id));

  /** Add a passkey to the signed-in account. */
  async function addPasskey(ctx, challenge, credential) {
    const { user } = await requireSession(ctx);
    throttle('signup', ctx);
    const ch = await openChallenge(challenge, 'add');
    if (ch.data.userId !== user.id) throw new HttpError(400, 'invalid_challenge');
    const cred = await verifyRegistration({ credential, expectedChallenge: challenge, expectedOrigin: origin, rpId }).catch(passkeyError);
    if (credentialTaken(cred.credentialId)) throw new HttpError(409, 'credential_exists', 'this passkey is already registered');
    spendChallenge(ch);
    user.credentials.push({ ...cred, created: now() });
    await save();
    return { user: publicUser(user) };
  }

  async function checkProof(ctx) {
    try {
      return await verifyProof(ctx.headers['bound-proof'], { method: ctx.method, url: ctx.fullUrl, body: ctx.body, replay: anonReplay });
    } catch (e) { throw new HttpError(e.code === 'busy' ? 503 : 401, e.code ?? 'invalid_proof', e.message); }
  }

  const server = createServer({
    origin, routes, nonces, rate: rates.http,
    staticDirs: { '/lib/': join(ROOT, 'src', 'lib'), '/': join(here, 'public') },
    // Only the protocol endpoints a client calls directly are open cross-origin.
    // They are authenticated by token + proof, never by cookies.
    cors: (ctx) => (['/bound/renew', '/bound/revoke', '/bound/request', '/bound/token', '/.well-known/bound-issuer'].includes(ctx.url.pathname)
      ? { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, bound-proof, content-type', 'access-control-allow-methods': 'GET, POST' }
      : {}),
    headers: {
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      'referrer-policy': 'no-referrer',
    },
  });
  return { server, origin, db, issuerKey, save: () => save(), listen: () => listen(server, cfg.port(origin)) };
}

function passkeyError(e) {
  if (e instanceof HttpError) throw e;
  if (e instanceof WebAuthnError) throw new HttpError(401, 'passkey_rejected', e.message);
  throw new HttpError(400, 'invalid_request', 'malformed passkey response');
}

function randomUserCode() {
  const alphabet = 'BCDFGHJKLMNPQRSTVWXZ';   // no vowels: no accidental words
  let s = '';
  while (s.length < 8) {
    const [b] = crypto.getRandomValues(new Uint8Array(1));
    if (b < 240) s += alphabet[b % alphabet.length];   // rejection sampling: no modulo bias
  }
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const issuer = await createIssuer();
  await issuer.listen();
  console.log(`issuer   ${issuer.origin}`);
}
