// Bound Tokens: a chain of signed blocks.
//
//   token  = "bnd1~" block *( "~" block )
//   block  = b64u(JSON payload) "." b64u(ES256 signature over the b64u payload)
//
// Block 0 is signed by the issuer. Every later block is signed by whoever holds
// the token at that point (the key named by the most recent `cnf`) and can only
// narrow what the token allows. A block may move the token to a new key
// (`cnf`), which is how delegation works. Possession of the token string alone
// is never enough to use it, extend it or delegate it.

import { b64uJson, unb64uJson, sha256b64u, now as nowSec, randomId } from './encoding.js';
import { sign, verify, thumbprint, importPublicJwk } from './keys.js';

export const PREFIX = 'bnd1';
export const MAX_BLOCKS = 8;
export const MAX_TOKEN_LENGTH = 16384;
export const CLOCK_SKEW = 60;

export class TokenError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, msg) => { throw new TokenError(code, msg); };

async function signBlock(privateKey, payload) {
  const p = b64uJson(payload);
  return `${p}.${await sign(privateKey, p)}`;
}

/** Split a token into blocks without verifying anything. */
export function parseToken(token) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) fail('malformed', 'token missing or too long');
  const parts = token.split('~');
  if (parts[0] !== PREFIX) fail('malformed', 'unknown token version');
  const raw = parts.slice(1);
  if (raw.length < 1 || raw.length > MAX_BLOCKS) fail('malformed', 'bad block count');
  return raw.map((b) => {
    const segs = b.split('.');
    if (segs.length !== 2) fail('malformed', 'bad block encoding');
    let payload;
    try { payload = unb64uJson(segs[0]); } catch { fail('malformed', 'bad block payload'); }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) fail('malformed', 'bad block payload');
    return { p: segs[0], s: segs[1], payload };
  });
}

/** Thumbprint of the key that currently holds the token (unverified). */
export function currentHolder(token) {
  let jkt;
  for (const { payload } of parseToken(token)) if (payload.cnf?.jkt) jkt = payload.cnf.jkt;
  return jkt;
}

/**
 * Issue a root token. `claims` must include sub, aud, cnf.jkt and grants.
 * Lifetime is short by design; see renewal in the spec.
 */
export async function issueToken(issuer, claims, { ttl = 300 } = {}) {
  const iat = nowSec();
  const payload = {
    ...claims,
    v: 1, typ: 'bound', iss: issuer.iss, kid: issuer.kid, jti: randomId(),
    iat, exp: iat + ttl,
  };
  if (typeof payload.sub !== 'string') fail('invalid_request', 'sub required');
  if (!Array.isArray(payload.aud) || payload.aud.length === 0) fail('invalid_request', 'aud required');
  if (typeof payload.cnf?.jkt !== 'string') fail('invalid_request', 'cnf.jkt required');
  if (!Array.isArray(payload.grants)) fail('invalid_request', 'grants required');
  return `${PREFIX}~${await signBlock(issuer.privateKey, payload)}`;
}

/**
 * Append an attenuation block. Only the current holder can do this.
 *   restrictions: { exp?, ttl?, aud?, grants?, to? (public JWK of the new holder) }
 */
export async function attenuate(token, holder, restrictions = {}) {
  const blocks = parseToken(token);
  if (blocks.length >= MAX_BLOCKS) fail('invalid_request', 'too many blocks');
  if (currentHolder(token) !== holder.jkt) fail('not_holder', 'only the current holder can attenuate');
  const iat = nowSec();
  const payload = {
    prev: await sha256b64u(blocks[blocks.length - 1].s),
    iat,
    by: holder.jwk,
  };
  if (restrictions.ttl != null) payload.exp = iat + restrictions.ttl;
  if (restrictions.exp != null) payload.exp = Math.min(payload.exp ?? Infinity, restrictions.exp);
  if (restrictions.aud) payload.aud = restrictions.aud;
  if (restrictions.grants) payload.grants = restrictions.grants;
  if (restrictions.to) payload.cnf = { jkt: await thumbprint(restrictions.to) };
  return `${token}~${await signBlock(holder.privateKey, payload)}`;
}

/**
 * Verify a token's signatures and time/audience constraints.
 *   opts.issuerKey(iss, kid) -> CryptoKey | null   (required)
 *   opts.issuer      expected issuer identifier     (required)
 *   opts.audience    this verifier's origin         (required)
 *   opts.now         override clock (seconds)
 *   opts.anyAudience skip the audience check (issuer renewal endpoint only)
 * Returns a VerifiedToken; authorization is a separate step (`allows`).
 */
export async function verifyToken(token, opts) {
  const { issuerKey, issuer, audience } = opts;
  const t = opts.now ?? nowSec();
  const blocks = parseToken(token);
  const root = blocks[0].payload;

  if (root.v !== 1 || root.typ !== 'bound') fail('malformed', 'not a Bound token');
  if (root.iss !== issuer) fail('invalid_issuer', 'unexpected issuer');
  const key = await issuerKey(root.iss, root.kid);
  if (!key) fail('invalid_issuer', 'unknown issuer key');
  if (!(await verify(key, blocks[0].s, blocks[0].p))) fail('invalid_signature', 'root signature invalid');
  if (typeof root.sub !== 'string' || !Array.isArray(root.aud) || typeof root.cnf?.jkt !== 'string' ||
      !Array.isArray(root.grants) || !Number.isInteger(root.exp) || !Number.isInteger(root.iat)) {
    fail('malformed', 'root block missing required claims');
  }

  let holder = root.cnf.jkt;
  let exp = root.exp;
  const grantSets = [root.grants];

  for (let i = 1; i < blocks.length; i++) {
    const { p, s, payload: b } = blocks[i];
    if (b.prev !== await sha256b64u(blocks[i - 1].s)) fail('malformed', `block ${i} not chained`);
    let by;
    try { by = await importPublicJwk(b.by); } catch { fail('malformed', `block ${i} signer key invalid`); }
    if (await thumbprint(b.by) !== holder) fail('invalid_signature', `block ${i} not signed by holder`);
    if (!(await verify(by, s, p))) fail('invalid_signature', `block ${i} signature invalid`);
    if (!Number.isInteger(b.iat) || b.iat < root.iat) fail('malformed', `block ${i} bad iat`);
    if (b.exp != null) {
      if (!Number.isInteger(b.exp)) fail('malformed', `block ${i} bad exp`);
      exp = Math.min(exp, b.exp);
    }
    if (b.aud != null && !Array.isArray(b.aud)) fail('malformed', `block ${i} bad aud`);
    if (b.grants != null) {
      if (!Array.isArray(b.grants)) fail('malformed', `block ${i} bad grants`);
      grantSets.push(b.grants);
    }
    if (b.cnf != null) {
      if (typeof b.cnf.jkt !== 'string') fail('malformed', `block ${i} bad cnf`);
      holder = b.cnf.jkt;
    }
  }

  if (root.iat > t + CLOCK_SKEW) fail('invalid_token', 'token issued in the future');
  if (t >= exp + CLOCK_SKEW) fail('expired', 'token expired');
  if (!opts.anyAudience) {
    if (typeof audience !== 'string') fail('invalid_request', 'verifier audience required');
    for (const { payload } of blocks) {
      if (payload.aud && !payload.aud.includes(audience)) fail('invalid_audience', 'token not intended for this audience');
    }
  }

  return {
    root, holder, exp, grantSets,
    blockCount: blocks.length,
    sub: root.sub,
    /** Is `action` on `url` permitted by every block? */
    allows: (url, action) => allows(grantSets, url, action),
  };
}

/** A request is permitted only if EVERY grant set (one per block) permits it. */
export function allows(grantSets, url, action) {
  let target;
  try { target = new URL(url); } catch { return false; }
  return grantSets.every((set) => set.some((g) => grantMatches(g, target, action)));
}

function grantMatches(grant, target, action) {
  if (!grant || typeof grant.res !== 'string' || !Array.isArray(grant.act)) return false;
  if (!grant.act.includes(action)) return false;
  let res;
  try { res = new URL(grant.res); } catch { return false; }
  if (res.origin !== target.origin) return false;
  // An encoded "/" or "\" would be a path separator to any server that decodes
  // before routing, but not to this prefix match. Refuse such paths outright.
  if (/%2f|%5c/i.test(target.pathname)) return false;
  if (res.pathname.endsWith('/')) return target.pathname.startsWith(res.pathname);
  return target.pathname === res.pathname;
}
