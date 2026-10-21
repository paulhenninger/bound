import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeHolder, generateKeyPair } from '../src/lib/keys.js';
import { issueToken, attenuate, verifyToken, parseToken, TokenError } from '../src/lib/token.js';
import { b64uJson, now } from '../src/lib/encoding.js';

const ISS = 'https://issuer.example';
const RS = 'https://api.example';

async function setup() {
  const kp = await generateKeyPair();
  const issuer = { iss: ISS, kid: 'k1', ...kp };
  const issuerKey = async (iss, kid) => (iss === ISS && kid === 'k1' ? kp.publicKey : null);
  const alice = await makeHolder();
  const token = await issueToken(issuer, {
    sub: 'u1', aud: [RS], cnf: { jkt: alice.jkt },
    grants: [{ res: `${RS}/notes/`, act: ['read', 'write'] }, { res: `${RS}/profile`, act: ['read'] }],
  });
  const verify = (t, o = {}) => verifyToken(t, { issuerKey, issuer: ISS, audience: RS, ...o });
  return { issuer, issuerKey, alice, token, verify };
}

const rejects = (p, code) => assert.rejects(p, (e) => e instanceof TokenError && e.code === code);

test('root token verifies and authorizes by grant', async () => {
  const { token, verify, alice } = await setup();
  const t = await verify(token);
  assert.equal(t.holder, alice.jkt);
  assert.ok(t.allows(`${RS}/notes/abc`, 'write'));
  assert.ok(t.allows(`${RS}/notes/`, 'read'));
  assert.ok(t.allows(`${RS}/profile`, 'read'));
  assert.ok(!t.allows(`${RS}/profile/x`, 'read'), 'non-slash grant is exact');
  assert.ok(!t.allows(`${RS}/profile`, 'write'));
  assert.ok(!t.allows(`${RS}/notes`, 'read'), 'prefix grant does not match its parent');
  assert.ok(!t.allows(`${RS}/notesx/1`, 'read'));
  assert.ok(!t.allows(`https://evil.example/notes/1`, 'read'));
  assert.ok(!t.allows(`${RS}/notes/../admin`, 'read'), 'dot segments are normalised before matching');
});

test('identity tokens (no grants) authorize nothing', async () => {
  const { issuer, issuerKey, alice } = await setup();
  const id = await issueToken(issuer, { sub: 'u', aud: [RS], cnf: { jkt: alice.jkt }, grants: [] });
  const t = await verifyToken(id, { issuerKey, issuer: ISS, audience: RS });
  assert.ok(!t.allows(`${RS}/notes/`, 'read'));
});

test('wrong audience, wrong issuer, unknown key are rejected', async () => {
  const { token, verify } = await setup();
  await rejects(verify(token, { audience: 'https://other.example' }), 'invalid_audience');
  await rejects(verify(token, { issuer: 'https://evil.example' }), 'invalid_issuer');
  await rejects(verify(token, { issuerKey: async () => null }), 'invalid_issuer');
});

test('expiry is enforced (with bounded skew)', async () => {
  const { token, verify } = await setup();
  const exp = parseToken(token)[0].payload.exp;
  await verify(token, { now: exp + 59 });
  await rejects(verify(token, { now: exp + 60 }), 'expired');
});

test('tampering with any byte of the root block breaks the signature', async () => {
  const { token, verify } = await setup();
  const [, block] = token.split('~');
  const [p, s] = block.split('.');
  const payload = parseToken(token)[0].payload;
  payload.grants.push({ res: `${RS}/admin/`, act: ['write'] });
  await rejects(verify(`bnd1~${b64uJson(payload)}.${s}`), 'invalid_signature');
  assert.ok(p);
});

test('attenuation narrows grants, audience and lifetime', async () => {
  const { token, verify, alice } = await setup();
  const narrowed = await attenuate(token, alice, { ttl: 30, grants: [{ res: `${RS}/notes/`, act: ['read'] }] });
  const t = await verify(narrowed);
  assert.ok(t.allows(`${RS}/notes/1`, 'read'));
  assert.ok(!t.allows(`${RS}/notes/1`, 'write'));
  assert.ok(!t.allows(`${RS}/profile`, 'read'));
  assert.ok(t.exp <= now() + 30);
  await rejects(verify(await attenuate(token, alice, { aud: ['https://elsewhere.example'] })), 'invalid_audience');
});

test('attenuation cannot widen: every block must allow the request', async () => {
  const { token, verify, alice } = await setup();
  const ro = await attenuate(token, alice, { grants: [{ res: `${RS}/notes/`, act: ['read'] }] });
  const widened = await attenuate(ro, alice, { grants: [{ res: `${RS}/`, act: ['read', 'write'] }] });
  const t = await verify(widened);
  assert.ok(!t.allows(`${RS}/notes/1`, 'write'));
  assert.ok(!t.allows(`${RS}/other`, 'read'));
});

test('delegation moves the token to a new key; the old holder loses it', async () => {
  const { token, verify, alice } = await setup();
  const bob = await makeHolder();
  const delegated = await attenuate(token, alice, { to: bob.jwk });
  assert.equal((await verify(delegated)).holder, bob.jkt);
  await assert.rejects(attenuate(delegated, alice, {}), (e) => e.code === 'not_holder');
  const further = await attenuate(delegated, bob, { grants: [{ res: `${RS}/notes/`, act: ['read'] }] });
  assert.equal((await verify(further)).holder, bob.jkt);
});

test('a thief cannot forge an attenuation or delegation block', async () => {
  const { token, verify } = await setup();
  const mallory = await makeHolder();
  // Forge a block signed by Mallory that claims to rebind the token to Mallory.
  const forgedHolder = { ...mallory };
  const blocks = parseToken(token);
  const { sha256b64u } = await import('../src/lib/encoding.js');
  const { sign, thumbprint } = await import('../src/lib/keys.js');
  const payload = { prev: await sha256b64u(blocks[0].s), iat: now(), by: forgedHolder.jwk, cnf: { jkt: await thumbprint(mallory.jwk) } };
  const p = b64uJson(payload);
  const forged = `${token}~${p}.${await sign(mallory.privateKey, p)}`;
  await rejects(verify(forged), 'invalid_signature');
});

test('blocks cannot be spliced between tokens', async () => {
  const { issuer, issuerKey, alice, token } = await setup();
  const other = await issueToken(issuer, { sub: 'u1', aud: [RS], cnf: { jkt: alice.jkt }, grants: [{ res: `${RS}/`, act: ['read'] }] });
  const narrowed = await attenuate(token, alice, { grants: [] });
  const splice = `${other}~${narrowed.split('~')[2]}`;
  await rejects(verifyToken(splice, { issuerKey, issuer: ISS, audience: RS }), 'malformed');
});

test('structural limits', async () => {
  const { token, verify, alice } = await setup();
  let t = token;
  for (let i = 0; i < 7; i++) t = await attenuate(t, alice, {});
  await verify(t);
  await assert.rejects(attenuate(t, alice, {}), /too many blocks/);
  await rejects(verify('bnd2~abc.def'), 'malformed');
  await rejects(verify('bnd1~'), 'malformed');
  await rejects(verify('x'.repeat(20000)), 'malformed');
});
