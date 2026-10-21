// Regression tests for the second review: slow passkey prompts, anonymous
// floods, per-address limits, bounded growth, key rotation and account tools.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIssuer } from '../src/issuer/server.js';
import { loadStore, saver, rotateKey } from '../src/issuer/store.js';
import { createRelyingParty } from '../src/rp/server.js';
import { createResourceServer } from '../src/rs/server.js';
import { makeHolder } from '../src/lib/keys.js';
import { utf8, now } from '../src/lib/encoding.js';
import { attenuate, parseToken } from '../src/lib/token.js';
import { boundFetch } from '../src/lib/client.js';
import { createProof } from '../src/lib/proof.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';
import { Browser, NO_RATE_LIMITS, fetchFrom } from './helpers/browser.js';

const ISSUER = 'http://localhost:5620';
const RP = 'http://localhost:5621';
const RS = 'http://localhost:5622';
const NOTES = `${RS}/notes/`;
const rsMap = { [RS]: { name: 'Notes API', actions: { read: 'Read', write: 'Write' } } };
const servers = [];
let dir, issuer;

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'bound-availability-'));
  issuer = await createIssuer({ origin: ISSUER, dataFile: join(dir, 'issuer.json'), resourceServers: rsMap, rates: NO_RATE_LIMITS });
  const rs = createResourceServer({ origin: RS, issuer: ISSUER, rate: false });
  const rp = await createRelyingParty({ origin: RP, issuer: ISSUER, rs: RS, rate: false });
  for (const s of [issuer, rs, rp]) { await s.listen(); servers.push(s.server); }
});
after(async () => {
  for (const s of servers) { s.closeAllConnections?.(); s.close(); }
  await rm(dir, { recursive: true, force: true });
});

const browser = (iss = ISSUER, f) => new Browser({ boundOrigins: [iss], fetch: f });
let userCount = 0;

async function registerUser(b, iss = ISSUER) {
  const auth = new SoftAuthenticator();
  const username = `user${++userCount}`;
  const o = await b.json(iss, `${iss}/webauthn/register/options`, { username });
  const r = await b.json(iss, `${iss}/webauthn/register/verify`, { challenge: o.data.challenge, credential: auth.create(o.data, iss) });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return { auth, username };
}

async function login(b, auth, iss = ISSUER) {
  const o = await b.json(iss, `${iss}/webauthn/login/options`);
  return b.json(iss, `${iss}/webauthn/login/verify`, { challenge: o.data.challenge, credential: auth.get(o.data, iss) });
}

async function authorize(b, { iss = ISSUER, agent, access = { aud: [RS], grants: [{ res: NOTES, act: ['read'] }] } } = {}) {
  agent ??= await makeHolder();
  const r = await b.json(iss, `${iss}/bound/authorize`, { rp: RP, nonce: 'n'.repeat(20), jkt: agent.jkt, access });
  return { agent, ...r };
}

/** One request signed by `key` with a chosen nonce, as boundFetch would send it. */
async function signedPost(key, url, json, nonce, cookie) {
  const body = utf8(JSON.stringify(json));
  const proof = await createProof(key, { method: 'POST', url, body, nonce });
  const res = await fetch(url, { method: 'POST', body, headers: { 'content-type': 'application/json', origin: new URL(url).origin, 'bound-proof': proof, ...(cookie ? { cookie } : {}) } });
  return { status: res.status, data: await res.json(), nonce: res.headers.get('bound-nonce'), cookie: res.headers.get('set-cookie')?.split(';')[0] };
}

// ---- 1: a slow passkey prompt must not cost the user their ceremony ---------------------

test('sign-up survives a stale nonce: the retry reuses the same challenge', async () => {
  const key = await makeHolder();
  const auth = new SoftAuthenticator();
  const o = await signedPost(key, `${ISSUER}/webauthn/register/options`, { username: 'slowsignup' });
  const credential = auth.create(o.data, ISSUER);
  const body = { challenge: o.data.challenge, credential };
  // The passkey prompt took longer than a nonce lives.
  const first = await signedPost(key, `${ISSUER}/webauthn/register/verify`, body, 'stale.nonce');
  assert.equal(first.status, 401);
  assert.equal(first.data.error, 'use_nonce');
  const retry = await signedPost(key, `${ISSUER}/webauthn/register/verify`, body, first.nonce);
  assert.equal(retry.status, 200, JSON.stringify(retry.data));
  // ...and the challenge is spent now.
  const again = await signedPost(key, `${ISSUER}/webauthn/register/verify`, body, retry.nonce);
  assert.equal(again.status, 400);
  assert.equal(again.data.error, 'invalid_challenge');
});

test('sign-in survives a stale nonce; a used assertion cannot be replayed', async () => {
  const { auth } = await registerUser(browser());
  const key = await makeHolder();
  const o = await signedPost(key, `${ISSUER}/webauthn/login/options`, {});
  const body = { challenge: o.data.challenge, credential: auth.get(o.data, ISSUER) };
  const first = await signedPost(key, `${ISSUER}/webauthn/login/verify`, body, 'stale.nonce');
  assert.equal(first.data.error, 'use_nonce');
  const retry = await signedPost(key, `${ISSUER}/webauthn/login/verify`, body, first.nonce);
  assert.equal(retry.status, 200, JSON.stringify(retry.data));
  const replayed = await signedPost(key, `${ISSUER}/webauthn/login/verify`, body, retry.nonce);
  assert.equal(replayed.data.error, 'invalid_challenge');
});

test('a forged or foreign challenge is refused', async () => {
  const { auth } = await registerUser(browser());
  const b = browser();
  const o = await b.json(ISSUER, `${ISSUER}/webauthn/login/options`);
  const forged = Buffer.from('eyJkIjp7ImtpbmQiOiJsb2dpbiJ9fQ.AAAAAAAAAAAAAAAAAAAAAA').toString('base64url');
  const r = await b.json(ISSUER, `${ISSUER}/webauthn/login/verify`, { challenge: forged, credential: auth.get({ ...o.data, challenge: forged }, ISSUER) });
  assert.equal(r.data.error, 'invalid_challenge');
  // A registration challenge can't be used to sign in.
  const reg = await b.json(ISSUER, `${ISSUER}/webauthn/register/options`, { username: 'kindcheck' });
  const r2 = await b.json(ISSUER, `${ISSUER}/webauthn/login/verify`, { challenge: reg.data.challenge, credential: auth.get({ challenge: reg.data.challenge }, ISSUER) });
  assert.equal(r2.data.error, 'invalid_challenge');
});

// ---- 2: anonymous floods lock nobody out -------------------------------------------------

test('flooding challenge and sign-in nonce endpoints locks nobody out', async () => {
  const flood = async (url) => {
    const out = [];
    for (let i = 0; i < 3000; i += 100) out.push(...await Promise.all(Array.from({ length: 100 }, () => fetch(url, { method: 'POST' }).then((r) => r.status))));
    return out;
  };
  const [a, b] = await Promise.all([flood(`${ISSUER}/webauthn/login/options`), flood(`${RP}/bound/nonce`)]);
  assert.ok(a.every((s) => s === 200) && b.every((s) => s === 200), 'nothing is stored, so nothing fills up');
  // A real user can still sign up, sign in, and sign in to the RP.
  const br = browser();
  const { auth } = await registerUser(br);
  assert.equal((await login(br, auth)).status, 200);
  const agent = await makeHolder();
  const { data: { nonce } } = await br.json(RP, `${RP}/bound/nonce`);
  const t = await br.json(ISSUER, `${ISSUER}/bound/authorize`, { rp: RP, nonce, jkt: agent.jkt });
  const s = await boundFetch(agent, `${RP}/bound/session`, { method: 'POST', token: t.data.identity, json: {}, fetch: br.fetchAs(RP) });
  assert.equal(s.status, 200, JSON.stringify(s.data));
});

test('sign-in nonces are sealed and single-use', async () => {
  const br = browser();
  await registerUser(br);
  const tryNonce = async (nonce) => {
    const agent = await makeHolder();
    const t = await br.json(ISSUER, `${ISSUER}/bound/authorize`, { rp: RP, nonce, jkt: agent.jkt });
    return boundFetch(agent, `${RP}/bound/session`, { method: 'POST', token: t.data.identity, json: {}, fetch: br.fetchAs(RP) });
  };
  assert.equal((await tryNonce('made-up-nonce-0123456789')).data.error, 'invalid_nonce');
  const { data: { nonce } } = await br.json(RP, `${RP}/bound/nonce`);
  assert.equal((await tryNonce(nonce)).status, 200);
  assert.equal((await tryNonce(nonce)).data.error, 'invalid_nonce', 'used once only');
});

test('anonymous Flow B traffic cannot fill the replay cache that sessions and renewal use', async () => {
  const iss = 'http://localhost:5625';
  const small = await createIssuer({ origin: iss, dataFile: join(dir, 'replay.json'), resourceServers: rsMap, rates: NO_RATE_LIMITS, limits: { replay: 20 } });
  await small.listen();
  servers.push(small.server);
  const b = browser(iss);
  await registerUser(b, iss);
  const { agent, data } = await authorize(b, { iss });
  const anon = await makeHolder();
  const statuses = [];
  for (let i = 0; i < 25; i++) statuses.push((await boundFetch(anon, `${iss}/bound/token`, { method: 'POST', json: { request_id: 'x' } })).status);
  assert.ok(statuses.includes(503), 'the anonymous cache fills and fails closed');
  assert.equal((await b.json(iss, `${iss}/api/session`, undefined, 'GET')).status, 200, 'sessions unaffected');
  assert.equal((await boundFetch(agent, `${iss}/bound/renew`, { method: 'POST', token: data.access })).status, 200, 'renewal unaffected');
});

// ---- 3: per-address limits stop one client, not everyone ---------------------------------

test('per-address limits: one address is throttled, others are not', async () => {
  const iss = 'http://localhost:5623';
  const limited = await createIssuer({ origin: iss, dataFile: join(dir, 'limited.json'), resourceServers: rsMap });
  await limited.listen();
  servers.push(limited.server);

  // Account creation: 5 at once, then one a minute.
  const bot = browser(iss, fetchFrom('127.0.0.2'));
  for (let i = 0; i < 5; i++) await registerUser(bot, iss);
  const o = await bot.json(iss, `${iss}/webauthn/register/options`, { username: 'onetoomany' });
  const sixth = await bot.json(iss, `${iss}/webauthn/register/verify`, { challenge: o.data.challenge, credential: new SoftAuthenticator().create(o.data, iss) });
  assert.equal(sixth.status, 429);
  assert.equal(sixth.data.error, 'rate_limited');
  await registerUser(browser(iss, fetchFrom('127.0.0.3')), iss);   // someone else is fine

  // Flow B requests: 10 at once per address.
  const ask = (f) => boundFetch(bot.keys.get(iss), `${iss}/bound/request`, { method: 'POST', fetch: f, json: { client_name: 'x', aud: [RS], grants: [{ res: NOTES, act: ['read'] }] } });
  const fromBot = [];
  for (let i = 0; i < 11; i++) fromBot.push((await ask(fetchFrom('127.0.0.2'))).status);
  assert.deepEqual([fromBot.slice(0, 10).every((s) => s === 200), fromBot[10]], [true, 429]);
  assert.equal((await ask(fetchFrom('127.0.0.4'))).status, 200);

  // Passkey sign-in attempts: 20 at once per address.
  const f5 = fetchFrom('127.0.0.5');
  const tries = [];
  for (let i = 0; i < 21; i++) {
    tries.push((await f5(`${iss}/webauthn/login/verify`, { method: 'POST', headers: { origin: iss, 'content-type': 'application/json' }, body: '{}' })).status);
  }
  assert.ok(tries.slice(0, 20).every((s) => s === 400) && tries[20] === 429, JSON.stringify(tries));

  // Everything else: a burst of 500 per address.
  const f6 = fetchFrom('127.0.0.6');
  const burst = [];
  const t0 = Date.now();
  for (let i = 0; i < 1500; i += 50) burst.push(...await Promise.all(Array.from({ length: 50 }, () => f6(`${iss}/.well-known/bound-issuer`).then((r) => r.status))));
  const allowed = burst.filter((s) => s === 200).length;
  assert.ok(allowed <= 500 + 50 * ((Date.now() - t0) / 1000 + 1), `${allowed} allowed`);
  assert.ok(burst.includes(429));
  const r = await f6(`${iss}/.well-known/bound-issuer`);
  assert.equal(r.status, 429);
  assert.ok(Number(r.headers.get('retry-after')) >= 1, 'says when to come back');
  assert.equal((await fetchFrom('127.0.0.7')(`${iss}/.well-known/bound-issuer`)).status, 200);
});

// ---- 4: bounded growth per user ------------------------------------------------------------

test('a user has at most 10 issuer sessions; signing in again ends the oldest', async () => {
  const first = browser();
  const { auth } = await registerUser(first);
  for (let i = 0; i < 10; i++) assert.equal((await login(browser(), auth)).status, 200);
  assert.equal((await first.json(ISSUER, `${ISSUER}/api/session`, undefined, 'GET')).status, 401);
});

test('a user has at most 10 RP sessions', async () => {
  const br = browser();
  await registerUser(br);
  const sessions = [];
  for (let i = 0; i < 11; i++) {
    const agent = await makeHolder();
    const rpb = new Browser();
    const { data: { nonce } } = await rpb.json(RP, `${RP}/bound/nonce`);
    const t = await br.json(ISSUER, `${ISSUER}/bound/authorize`, { rp: RP, nonce, jkt: agent.jkt });
    assert.equal((await boundFetch(agent, `${RP}/bound/session`, { method: 'POST', token: t.data.identity, json: {}, fetch: rpb.fetchAs(RP) })).status, 200);
    sessions.push({ agent, rpb });
  }
  const me = ({ agent, rpb }) => boundFetch(agent, `${RP}/api/me`, { fetch: rpb.fetchAs(RP) });
  assert.equal((await me(sessions[0])).status, 401, 'oldest ended');
  assert.equal((await me(sessions[10])).status, 200);
});

test('a user has at most 100 live grants', async () => {
  const br = browser();
  await registerUser(br);
  for (let i = 0; i < 100; i++) assert.equal((await authorize(br)).status, 200);
  const r = await authorize(br);
  assert.equal(r.status, 409);
  assert.equal(r.data.error, 'too_many_grants');
  // Identity-only sign-in records no grant, so it still works.
  assert.equal((await authorize(br, { access: null })).status, 200);
});

test('grants whose renewal window closed are forgotten, and say so', async () => {
  const br = browser();
  await registerUser(br);
  const { agent, data } = await authorize(br);
  const gid = parseToken(data.access)[0].payload.gid;
  issuer.db.grants[gid].rex = now() - 1;
  await authorize(br);   // any grant change prunes dead grants
  assert.ok(!(gid in issuer.db.grants));
  const r = await boundFetch(agent, `${ISSUER}/bound/renew`, { method: 'POST', token: data.access });
  assert.equal(r.data.error, 'renewal_window_closed');
  assert.equal((await boundFetch(agent, `${ISSUER}/bound/revoke`, { method: 'POST', token: data.access })).status, 200, 'revoking an ended grant is fine');
});

test('revoking twice is fine (same outcome)', async () => {
  const br = browser();
  await registerUser(br);
  const { agent, data } = await authorize(br);
  for (let i = 0; i < 2; i++) assert.equal((await boundFetch(agent, `${ISSUER}/bound/revoke`, { method: 'POST', token: data.access })).status, 200);
});

test('signing in does not rewrite the store when the passkey counter stays at 0', async () => {
  const br = browser();
  const { auth } = await registerUser(br);
  auth.creds[0].counter = -1;   // like most passkeys: always reports 0
  const file = join(dir, 'issuer.json');
  await issuer.save();
  const before = (await stat(file)).mtimeMs;
  await new Promise((r) => setTimeout(r, 20));
  assert.equal((await login(browser(), auth)).status, 200);
  await issuer.save().then(() => {}, () => {});   // flush any queued write
  assert.equal((await stat(file)).mtimeMs >= before, true);
  auth.creds[0].counter = -1;
  const before2 = (await stat(file)).mtimeMs;
  await new Promise((r) => setTimeout(r, 20));
  assert.equal((await login(browser(), auth)).status, 200);
  assert.equal((await stat(file)).mtimeMs, before2, 'no write');
});

// ---- 5: account tools -------------------------------------------------------------------------

test('add a second passkey, remove the first, then delete the account', async () => {
  const br = browser();
  const { auth, username } = await registerUser(br);
  const o = await br.json(ISSUER, `${ISSUER}/webauthn/register/options`, { add: true });
  assert.equal(o.status, 200);
  assert.equal(o.data.excludeCredentials.length, 1, 'the existing passkey is excluded');
  const second = new SoftAuthenticator();
  const added = await br.json(ISSUER, `${ISSUER}/webauthn/register/verify`, { challenge: o.data.challenge, credential: second.create(o.data, ISSUER) });
  assert.equal(added.status, 200, JSON.stringify(added.data));
  assert.equal(added.data.user.passkeys.length, 2);
  assert.equal((await login(browser(), second)).status, 200, 'the new passkey signs in');

  // Someone else's session can't spend this "add" challenge.
  const other = browser();
  await registerUser(other);
  const o2 = await br.json(ISSUER, `${ISSUER}/webauthn/register/options`, { add: true });
  const stolen = await other.json(ISSUER, `${ISSUER}/webauthn/register/verify`, { challenge: o2.data.challenge, credential: new SoftAuthenticator().create(o2.data, ISSUER) });
  assert.equal(stolen.data.error, 'invalid_challenge');

  const firstId = added.data.user.passkeys[0].id;
  const del = await br.json(ISSUER, `${ISSUER}/api/passkeys/${encodeURIComponent(firstId)}/delete`);
  assert.equal(del.data.user.passkeys.length, 1);
  assert.equal((await login(browser(), auth)).data.error, 'unknown_credential');
  const last = await br.json(ISSUER, `${ISSUER}/api/passkeys/${encodeURIComponent(del.data.user.passkeys[0].id)}/delete`);
  assert.equal(last.data.error, 'last_passkey');

  await authorize(br);
  assert.equal((await br.json(ISSUER, `${ISSUER}/api/account/delete`, { username: 'wrong' })).status, 400);
  assert.equal((await br.json(ISSUER, `${ISSUER}/api/account/delete`, { username })).status, 200);
  assert.equal((await login(browser(), second)).data.error, 'unknown_credential');
  assert.equal((await br.json(ISSUER, `${ISSUER}/api/session`, undefined, 'GET')).status, 401);
});

// ---- 6: key rotation ---------------------------------------------------------------------------

test('key rotation: old tokens keep working until their key retires', async () => {
  const iss = 'http://localhost:5626';
  const file = join(dir, 'rotate.json');
  const start = async () => {
    const i = await createIssuer({ origin: iss, dataFile: file, resourceServers: rsMap, rates: NO_RATE_LIMITS });
    await i.listen();
    return i;
  };
  const stop = (i) => new Promise((r) => { i.server.closeAllConnections(); i.server.close(r); });
  const rsCheck = async (agent, token, port) => {
    const rs = createResourceServer({ origin: `http://localhost:${port}`, issuer: iss, rate: false });
    await rs.listen();
    try {
      const t = await attenuate(token, agent, { aud: [`http://localhost:${port}`] });
      return await boundFetch(agent, `http://localhost:${port}/notes/`, { token: t });
    } finally { await new Promise((r) => { rs.server.closeAllConnections(); rs.server.close(r); }); }
  };

  let i1 = await start();
  const b = browser(iss);
  await registerUser(b, iss);
  const { agent, data } = await authorize(b, { iss, access: { aud: [RS], grants: [{ res: NOTES, act: ['read'] }] } });
  const k1 = parseToken(data.access)[0].payload.kid;
  await stop(i1);

  const { db } = await loadStore(file);
  await rotateKey(db, { keepFor: 3600 });
  await saver(file, db)();
  const i2 = await start();
  const md = await (await fetch(`${iss}/.well-known/bound-issuer`)).json();
  assert.equal(md.keys.length, 2, 'old and new keys both published');
  const renewed = await boundFetch(agent, `${iss}/bound/renew`, { method: 'POST', token: data.access });
  assert.equal(renewed.status, 200, 'a token signed by the old key is still renewable');
  assert.notEqual(parseToken(renewed.data.access)[0].payload.kid, k1, 'new tokens use the new key');
  await stop(i2);

  const later = await loadStore(file);
  later.db.keys[0].retireAt = now() - 1;
  await saver(file, later.db)();
  i1 = await start();
  const md2 = await (await fetch(`${iss}/.well-known/bound-issuer`)).json();
  assert.deepEqual(md2.keys.map((k) => k.kid), [parseToken(renewed.data.access)[0].payload.kid], 'retired key removed');
  assert.ok(!(await loadStore(file)).db.keys.some((k) => k.kid === k1), 'and dropped from the file');
  const r = await boundFetch(agent, `${iss}/bound/renew`, { method: 'POST', token: data.access });
  assert.equal(r.data.error, 'invalid_issuer');
  await stop(i1);
});

test('issuer data from before key rotation is migrated', async () => {
  const file = join(dir, 'legacy.json');
  const { db } = await loadStore(join(dir, 'does-not-exist.json'));
  const { kid, key } = db.keys[0];
  await writeFile(file, JSON.stringify({ kid, key, pairwiseSecret: db.pairwiseSecret, users: {}, grants: {} }));
  const migrated = await loadStore(file);
  assert.deepEqual(migrated.db.keys.map((k) => k.kid), [kid]);
  assert.ok(!('key' in migrated.db) && !('kid' in migrated.db));
  // Starting an issuer on it writes the new layout back.
  const i = await createIssuer({ origin: 'http://localhost:5627', dataFile: file, resourceServers: rsMap });
  const onDisk = JSON.parse(await readFile(file, 'utf8'));
  assert.deepEqual(onDisk.keys.map((k) => k.kid), [kid]);
  assert.ok(!('key' in onDisk));
  assert.ok(i.db.keys.length === 1);
});

test('npm run rotate-key refuses while the issuer is running', async () => {
  const code = await new Promise((resolve) => {
    const p = spawn(process.execPath, ['src/issuer/rotate-key.js'], {
      env: { ...process.env, BOUND_ISSUER: ISSUER, BOUND_ISSUER_DATA: join(dir, 'issuer.json') }, stdio: 'ignore',
    });
    p.on('exit', resolve);
  });
  assert.equal(code, 1);
  assert.ok(JSON.parse(await readFile(join(dir, 'issuer.json'), 'utf8')).keys.length === 1, 'file untouched');
});
