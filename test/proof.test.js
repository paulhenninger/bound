import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeHolder, importPublicJwk } from '../src/lib/keys.js';
import { createProof, verifyProof, ReplayCache, ProofError } from '../src/lib/proof.js';
import { utf8, b64uJson, now } from '../src/lib/encoding.js';

const URL1 = 'https://api.example/notes/?q=1';
const body = utf8('{"text":"hi"}');
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof ProofError && e.code === code);

test('a proof verifies for exactly the request it was made for', async () => {
  const k = await makeHolder();
  const proof = await createProof(k, { method: 'POST', url: URL1, body, token: 'tok' });
  const v = await verifyProof(proof, { method: 'POST', url: URL1, body, token: 'tok', replay: new ReplayCache() });
  assert.equal(v.jkt, k.jkt);
});

test('method, URL, query, body and token are all bound', async () => {
  const k = await makeHolder();
  const opts = { method: 'POST', url: URL1, body, token: 'tok' };
  const check = async (override) => verifyProof(await createProof(k, opts), { ...opts, ...override, replay: new ReplayCache() });
  await rejects(check({ method: 'PUT' }), 'invalid_proof');
  await rejects(check({ url: 'https://api.example/notes/?q=2' }), 'invalid_proof');
  await rejects(check({ url: 'https://evil.example/notes/?q=1' }), 'invalid_proof');
  await rejects(check({ body: utf8('{"text":"bye"}') }), 'invalid_proof');
  await rejects(check({ token: 'other' }), 'invalid_proof');
  await rejects(check({ token: undefined }), 'invalid_proof');
});

test('proofs cannot be replayed', async () => {
  const k = await makeHolder();
  const replay = new ReplayCache();
  const opts = { method: 'GET', url: URL1 };
  const proof = await createProof(k, opts);
  await verifyProof(proof, { ...opts, replay });
  await rejects(verifyProof(proof, { ...opts, replay }), 'replayed');
});

test('stale and future proofs are rejected', async () => {
  const k = await makeHolder();
  const opts = { method: 'GET', url: URL1 };
  const proof = await createProof(k, opts);
  await rejects(verifyProof(proof, { ...opts, replay: new ReplayCache(), now: now() + 120 }), 'invalid_proof');
  await rejects(verifyProof(proof, { ...opts, replay: new ReplayCache(), now: now() - 120 }), 'invalid_proof');
});

test('a proof signed by a different key than it claims fails', async () => {
  const k = await makeHolder(), m = await makeHolder();
  const proof = await createProof(k, { method: 'GET', url: URL1 });
  const [p, s] = proof.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url'));
  payload.jwk = m.jwk;
  await rejects(verifyProof(`${b64uJson(payload)}.${s}`, { method: 'GET', url: URL1, replay: new ReplayCache() }), 'invalid_proof');
});

test('only P-256 keys are accepted (no algorithm negotiation)', async () => {
  await assert.rejects(importPublicJwk({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }));
  await assert.rejects(importPublicJwk({ kty: 'oct', k: 'c2VjcmV0' }));
  await assert.rejects(importPublicJwk({ kty: 'EC', crv: 'P-384', x: 'AAAA', y: 'AAAA' }));
  const k = await makeHolder();
  await assert.rejects(importPublicJwk({ ...k.jwk, d: 'AAAA' }), 'private keys are refused');
});
