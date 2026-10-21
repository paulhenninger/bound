// Regression tests for the security review: library-level fixes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeHolder, sign, verify } from '../src/lib/keys.js';
import { createProof, verifyProof, ReplayCache, NonceIssuer, ProofError } from '../src/lib/proof.js';
import { allows } from '../src/lib/token.js';
import { b64u, b64uJson, unb64u, sha256b64u, randomId, now } from '../src/lib/encoding.js';
import { ExpiringMap, CapacityError } from '../src/lib/state.js';
import { IssuerDirectory, IssuerUnavailableError } from '../src/lib/verifier.js';
import { parseCookies, cookie } from '../src/lib/http.js';
import { isAllowedRpOrigin } from '../src/lib/origins.js';
import { verifyRegistration, WebAuthnError } from '../src/lib/webauthn.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const URL1 = 'https://rp.example/api/me';
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof ProofError && e.code === code);

/** Sign a proof payload by hand, e.g. with a chosen iat (what pre-signing script would do). */
async function handProof(holder, fields) {
  const payload = { typ: 'bound-proof', jwk: holder.jwk, htm: 'GET', htu: URL1, iat: now(), jti: randomId(), bdy: await sha256b64u(new Uint8Array(0)), ...fields };
  const p = b64uJson(payload);
  return `${p}.${await sign(holder.privateKey, p)}`;
}

// ---- H2: proofs can't be signed ahead of time where nonces are required ----

test('a proof pre-signed for a future time is refused when a server nonce is required', async () => {
  const k = await makeHolder();
  const nonces = new NonceIssuer();
  const later = now() + 3600;
  // Without nonces this is the attack: signed now, valid in an hour.
  const presigned = await handProof(k, { iat: later });
  await verifyProof(presigned, { method: 'GET', url: URL1, replay: new ReplayCache(), now: later });
  // With nonces it fails: there is no way to know the nonce for a future window.
  await rejects(verifyProof(await handProof(k, { iat: later, jti: randomId() }), { method: 'GET', url: URL1, replay: new ReplayCache(), nonces, now: later }), 'use_nonce');
  const guessed = `${Math.floor(later / 30)}.${'A'.repeat(22)}`;
  await rejects(verifyProof(await handProof(k, { iat: later, nonce: guessed }), { method: 'GET', url: URL1, replay: new ReplayCache(), nonces, now: later }), 'use_nonce');
});

test('server nonces: current and previous window accepted, older or foreign ones refused', async () => {
  const nonces = new NonceIssuer({ window: 30 });
  const t = now();
  const n = await nonces.current(t);
  assert.ok(await nonces.valid(n, t));
  assert.ok(await nonces.valid(n, t + 30), 'previous window still accepted');
  assert.ok(!(await nonces.valid(n, t + 61)), 'expired after two windows');
  assert.ok(!(await nonces.valid(await new NonceIssuer().current(t), t)), 'another server\'s nonce');
  for (const bad of [undefined, 42, '', 'x', '1.2.3', `${Math.floor(t / 30)}`, 'x'.repeat(100)]) assert.ok(!(await nonces.valid(bad, t)));
  const k = await makeHolder();
  const proof = await createProof(k, { method: 'GET', url: URL1, nonce: n });
  await verifyProof(proof, { method: 'GET', url: URL1, replay: new ReplayCache(), nonces });
});

test('proof jti must carry 128 bits', async () => {
  const k = await makeHolder();
  await rejects(verifyProof(await handProof(k, { jti: 'a'.repeat(16) }), { method: 'GET', url: URL1, replay: new ReplayCache() }), 'invalid_proof');
  await verifyProof(await handProof(k, { jti: 'a'.repeat(22) }), { method: 'GET', url: URL1, replay: new ReplayCache() });
});

test('replay cache fails closed when full instead of forgetting live entries', () => {
  const rc = new ReplayCache({ max: 3 });
  for (let i = 0; i < 3; i++) assert.ok(rc.add(`j${i}`, now() + 100));
  assert.throws(() => rc.add('j3', now() + 100), (e) => e instanceof ProofError && e.code === 'busy');
  assert.equal(rc.add('j0', now() + 100), false, 'still remembers what it saw');
});

// ---- L4: signature malleability -----------------------------------------

test('signatures are always low-S, and high-S twins are refused', async () => {
  const k = await makeHolder();
  for (let i = 0; i < 20; i++) {
    const sig = unb64u(await sign(k.privateKey, `m${i}`));
    const s = sig.subarray(32).reduce((n, b) => (n << 8n) | BigInt(b), 0n);
    assert.ok(s <= N >> 1n, 'low S');
    const twin = new Uint8Array(sig);
    let hi = N - s;
    for (let j = 63; j >= 32; j--) { twin[j] = Number(hi & 0xffn); hi >>= 8n; }
    // Same signature, other encoding: WebCrypto would accept it; Bound must not.
    assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k.publicKey, twin, new TextEncoder().encode(`m${i}`)));
    assert.equal(await verify(k.publicKey, b64u(twin), `m${i}`), false);
    assert.equal(await verify(k.publicKey, b64u(sig), `m${i}`), true);
  }
});

// ---- M2: encoded separators in request paths ------------------------------

test('grants never match paths containing an encoded slash or backslash', () => {
  const gs = [[{ res: 'https://n.example/notes/', act: ['read'] }]];
  assert.ok(allows(gs, 'https://n.example/notes/abc', 'read'));
  for (const p of ['/notes/..%2Fadmin', '/notes/..%2fadmin', '/notes/%2F%2Fx', '/notes/..%5Cadmin', '/notes/a%5cb']) {
    assert.ok(!allows(gs, `https://n.example${p}`, 'read'), p);
  }
  assert.ok(!allows([[{ res: 'https://n.example/a%2Fb', act: ['read'] }]], 'https://n.example/a%2Fb', 'read'));
});

// ---- M7: bounded state ------------------------------------------------------

test('ExpiringMap: entries expire, are single-use with take(), and capacity is enforced', () => {
  const m = new ExpiringMap({ max: 2 });
  m.set('a', 1, now() + 60);
  m.set('old', 2, now() - 1);
  assert.equal(m.get('old'), undefined, 'expired entries are invisible');
  m.set('b', 3, now() + 60);   // the expired entry is swept to make room
  assert.throws(() => m.set('c', 4, now() + 60), CapacityError);
  m.set('a', 5, now() + 60);   // replacing an existing key is always fine
  assert.equal(m.take('a'), 5);
  assert.equal(m.take('a'), undefined);
  assert.deepEqual([...m.values()], [3]);
});

// ---- L2: issuer outages -----------------------------------------------------

test('IssuerDirectory: an unreachable issuer gives a clear error and is not hammered', async () => {
  let calls = 0;
  const dir = new IssuerDirectory('https://id.example', { fetch: async () => { calls++; throw new TypeError('fetch failed'); } });
  for (let i = 0; i < 10; i++) await assert.rejects(dir.key('https://id.example', 'k'), IssuerUnavailableError);
  assert.equal(calls, 1, 'backs off after a failure');
});

test('IssuerDirectory: concurrent lookups share one fetch, and keys never vanish mid-refresh', async () => {
  const { generateKeyPair } = await import('../src/lib/keys.js');
  const kp = await generateKeyPair({ extractable: true });
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const md = { issuer: 'https://id.example', keys: ['K0', 'K1'].map((kid) => ({ kty, crv, x, y, kid })) };
  let calls = 0;
  const dir = new IssuerDirectory('https://id.example', { minInterval: 0, fetch: async () => { calls++; await new Promise((r) => setTimeout(r, 10)); return { ok: true, json: async () => md }; } });
  const first = await Promise.all(Array.from({ length: 10 }, () => dir.key('https://id.example', 'K0')));
  assert.equal(calls, 1);
  assert.ok(first.every(Boolean));
  const during = [dir.key('https://id.example', 'unknown')];
  for (let i = 0; i < 50; i++) { during.push(dir.key('https://id.example', 'K1')); await new Promise((r) => setImmediate(r)); }
  const out = await Promise.all(during);
  assert.equal(out[0], null);
  assert.ok(out.slice(1).every(Boolean), 'known kid always found');
});

// ---- H1 / L7: HTTP helpers ----------------------------------------------------

test('cookie parsing never throws on malformed input', () => {
  assert.deepEqual(parseCookies('a=%E0%A4%A; b=1; c=x=y; =z; d'), { b: '1', c: 'x=y' });
  assert.deepEqual(parseCookies(undefined), {});
  assert.deepEqual(parseCookies('a=1; a=2'), { a: '1' }, 'first value wins');
});

test('cookies are Secure whenever the origin is HTTPS', () => {
  assert.match(cookie('https://rp.example', 'sid', 'v', 60), /; Secure$/);
  assert.doesNotMatch(cookie('http://localhost:4200', 'sid', 'v', 60), /Secure/);
  assert.match(cookie('https://rp.example', 'sid', 'v', 60), /HttpOnly; SameSite=Lax/);
});

test('RP origins: HTTPS anywhere, plain HTTP only on loopback', () => {
  for (const o of ['https://rp.example', 'http://localhost:4200', 'http://127.0.0.1:8080', 'http://[::1]:3000']) assert.ok(isAllowedRpOrigin(o), o);
  for (const o of ['http://rp.example', 'null', 'file://', 'chrome-extension://abc', 'https://rp.example/', 'https://rp.example/path', 'data:text/html,x', 42, undefined]) {
    assert.ok(!isAllowedRpOrigin(o), String(o));
  }
});

// ---- L1: passkey registration --------------------------------------------------

test('registration: the credential id must be the one in the authenticator data', async () => {
  const opts = { challenge: 'Y2hhbGxlbmdlLXJlZ2lzdHJhdGlvbi0x', rp: { id: 'id.example' }, user: { id: 'dXNlcjE' } };
  const reg = (credential) => verifyRegistration({ credential, expectedChallenge: opts.challenge, expectedOrigin: 'https://id.example', rpId: 'id.example' });
  const a = new SoftAuthenticator();
  await reg(a.create(opts, 'https://id.example'));
  const swapped = a.create(opts, 'https://id.example');
  swapped.id = b64u(new Uint8Array(16).fill(7));   // claim someone else's credential id
  await assert.rejects(reg(swapped), (e) => e instanceof WebAuthnError && /does not match/.test(e.message));
  await assert.rejects(reg(a.create(opts, 'https://id.example', { flags: 0x05 })), /no attested credential data/);
});
