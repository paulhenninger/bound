// Regression tests for the security review, end to end over real HTTP.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { mkdtemp, rm, readFile, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIssuer } from '../src/issuer/server.js';
import { createRelyingParty } from '../src/rp/server.js';
import { createResourceServer } from '../src/rs/server.js';
import { makeHolder, sign } from '../src/lib/keys.js';
import { b64uJson, sha256b64u, randomId, now } from '../src/lib/encoding.js';
import { attenuate, parseToken } from '../src/lib/token.js';
import { boundFetch } from '../src/lib/client.js';
import { createProof } from '../src/lib/proof.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';
import { Browser } from './helpers/browser.js';

const ISSUER = 'http://localhost:5600';
const RP = 'http://localhost:5601';
const RS = 'http://localhost:5602';
const NOTES = `${RS}/notes/`;
const rsMap = { [RS]: { name: 'Notes API', actions: { read: 'Read', write: 'Write' } } };
const servers = [];
let dir, issuer, rp;

const newBrowser = () => new Browser({ boundOrigins: [ISSUER] });

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'bound-hardening-'));
  issuer = await createIssuer({ origin: ISSUER, dataFile: join(dir, 'issuer.json'), resourceServers: rsMap });
  const rs = createResourceServer({ origin: RS, issuer: ISSUER });
  rp = await createRelyingParty({ origin: RP, issuer: ISSUER, rs: RS });
  for (const s of [issuer, rs, rp]) { await s.listen(); servers.push(s.server); }
});
after(async () => {
  for (const s of servers) s.close();
  await rm(dir, { recursive: true, force: true });
});

async function registerUser(b, username, displayName = username.toUpperCase()) {
  const auth = new SoftAuthenticator();
  const o = await b.json(ISSUER, `${ISSUER}/webauthn/register/options`, { username, displayName });
  assert.equal(o.status, 200, JSON.stringify(o.data));
  const credential = auth.create(o.data, ISSUER);
  const r = await b.json(ISSUER, `${ISSUER}/webauthn/register/verify`, { challenge: o.data.challenge, credential });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return { auth, credential };
}

async function signIn(b, { grants = [{ res: NOTES, act: ['read', 'write'] }], agent } = {}) {
  agent ??= await makeHolder();
  const rpFetch = b.fetchAs(RP);
  const cfg = await (await rpFetch(`${RP}/bound/config`)).json();
  const { data: { nonce } } = await b.json(RP, `${RP}/bound/nonce`);
  const tokens = await b.json(ISSUER, `${ISSUER}/bound/authorize`, {
    rp: RP, nonce, jkt: agent.jkt, claims: ['name'], access: grants ? { aud: [RS], grants } : undefined,
  });
  assert.equal(tokens.status, 200, JSON.stringify(tokens.data));
  const delegated = tokens.data.access ? await attenuate(tokens.data.access, agent, { to: cfg.serverKey }) : undefined;
  const session = await boundFetch(agent, `${RP}/bound/session`, { method: 'POST', token: tokens.data.identity, json: { access: delegated }, fetch: rpFetch });
  assert.equal(session.status, 200, JSON.stringify(session.data));
  return { agent, tokens: tokens.data, rpFetch };
}

/** Send raw bytes; resolve with the status line (or the socket error). */
const raw = (port, text) => new Promise((resolve) => {
  const s = net.connect(port, '127.0.0.1', () => s.write(text));
  let out = '';
  s.on('data', (d) => { out += d; });
  s.on('close', () => resolve(out.split('\r\n')[0]));
  s.on('error', (e) => resolve(`error ${e.code}`));
});

// ---- H1: hostile requests can't take a server down ----------------------------

test('malformed cookies, targets and paths get an error response, never a crash', async () => {
  for (const origin of [ISSUER, RP, RS]) {
    const port = new URL(origin).port;
    const bad = [
      'GET / HTTP/1.1\r\nHost: x\r\nCookie: a=%E0%A4%A\r\nConnection: close\r\n\r\n',
      'GET /notes/ HTTP/1.1\r\nHost: x\r\nCookie: rp_sid=%; bound_idp=%zz\r\nConnection: close\r\n\r\n',
      'GET //evil.example/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n',
      'DELETE /notes/%E0%A4%A HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n',
      'POST /api/notes HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]',
    ];
    for (const req of bad) assert.match(await raw(port, req), /^HTTP\/1\.1 [2-5]\d\d/, `${origin}: ${req.split('\r\n')[0]}`);
    // Still alive.
    assert.equal((await fetch(`${origin}/definitely-not-here`)).status, 404);
  }
});

// ---- H2: RP sessions need fresh server nonces and expire server-side ------------

test('session proofs must carry a fresh server nonce; pre-signed proofs are refused', async () => {
  const b = newBrowser();
  await registerUser(b, 'nonce');
  const { agent, rpFetch } = await signIn(b);
  // A proof without a nonce (e.g. one signed in advance by injected script) is refused,
  // and the server says which nonce to use.
  const proof = await createProof(agent, { method: 'GET', url: `${RP}/api/me` });
  const r = await rpFetch(`${RP}/api/me`, { headers: { 'bound-proof': proof } });
  assert.equal(r.status, 401);
  assert.equal((await r.json()).error, 'use_nonce');
  assert.ok(r.headers.get('bound-nonce'));
  // A proof dated an hour ahead with a made-up nonce is refused too.
  const p = { typ: 'bound-proof', jwk: agent.jwk, htm: 'GET', htu: `${RP}/api/me`, iat: now() + 30, jti: randomId(),
    bdy: await sha256b64u(new Uint8Array(0)), nonce: `${Math.floor(now() / 30) + 120}.AAAAAAAAAAAAAAAAAAAAAA` };
  const enc = b64uJson(p);
  const forged = await rpFetch(`${RP}/api/me`, { headers: { 'bound-proof': `${enc}.${await sign(agent.privateKey, enc)}` } });
  assert.equal((await forged.json()).error, 'use_nonce');
  // boundFetch picks up the server's nonce and succeeds.
  assert.equal((await boundFetch(agent, `${RP}/api/me`, { fetch: rpFetch })).status, 200);
});

test('RP sessions expire on the server, whatever the cookie says', async () => {
  const b = newBrowser();
  await registerUser(b, 'expiry');
  const { agent, rpFetch } = await signIn(b);
  assert.equal((await boundFetch(agent, `${RP}/api/me`, { fetch: rpFetch })).status, 200);
  const sid = b.jar.get(RP).split('=')[1];
  const s = rp.sessions.get(sid);
  rp.sessions.set(sid, s, now() - 1);   // as if the idle or absolute limit had passed
  const r = await boundFetch(agent, `${RP}/api/me`, { fetch: rpFetch });
  assert.equal(r.status, 401);
  assert.equal(r.data.error, 'no_session');
});

// ---- L3: logout needs the key ---------------------------------------------------

test('a stolen RP cookie cannot log the victim out', async () => {
  const b = newBrowser();
  await registerUser(b, 'logout');
  const { agent, rpFetch } = await signIn(b);
  const cookie = b.jar.get(RP);
  const thief = await fetch(`${RP}/api/logout`, { method: 'POST', headers: { cookie, origin: RP } });
  assert.equal((await thief.json()).ok, false);
  assert.equal((await boundFetch(agent, `${RP}/api/me`, { fetch: rpFetch })).status, 200);
  const real = await boundFetch(agent, `${RP}/api/logout`, { method: 'POST', fetch: rpFetch });
  assert.equal(real.data.ok, true);
  b.jar.set(RP, cookie);
  assert.equal((await boundFetch(agent, `${RP}/api/me`, { fetch: rpFetch })).status, 401);
});

// ---- SPEC §13: device-bound issuer session --------------------------------------

test('the issuer session cookie is useless without the page key', async () => {
  const b = newBrowser();
  await registerUser(b, 'idpcookie');
  assert.equal((await b.json(ISSUER, `${ISSUER}/api/session`, undefined, 'GET')).status, 200);
  const cookie = b.jar.get(ISSUER);
  const bare = await fetch(`${ISSUER}/api/session`, { headers: { cookie } });
  assert.equal(bare.status, 401);
  const thief = await boundFetch(await makeHolder(), `${ISSUER}/api/grants`, { fetch: (u, i) => fetch(u, { ...i, headers: { ...i.headers, cookie } }) });
  assert.equal(thief.status, 401);
  assert.equal(thief.data.error, 'invalid_proof');
  const auth = await fetch(`${ISSUER}/bound/authorize`, { method: 'POST', headers: { cookie, origin: ISSUER, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(auth.status, 401);
});

// ---- M1: Flow B revocation before collection --------------------------------------

async function flowBRequest(name = 'Test CLI', grants = [{ res: NOTES, act: ['read'] }]) {
  const cli = await makeHolder();
  const req = await boundFetch(cli, `${ISSUER}/bound/request`, { method: 'POST', json: { client_name: name, aud: [RS], grants } });
  return { cli, req };
}

test('Flow B: a grant revoked before collection yields no token', async () => {
  const b = newBrowser();
  await registerUser(b, 'revokerace');
  const { cli, req } = await flowBRequest();
  await b.json(ISSUER, `${ISSUER}/bound/interaction/decide`, { user_code: req.data.user_code, approve: true });
  const { data: { grants } } = await b.json(ISSUER, `${ISSUER}/api/grants`, undefined, 'GET');
  assert.equal((await b.json(ISSUER, `${ISSUER}/api/grants/${grants[0].gid}/revoke`)).status, 200);
  const col = await boundFetch(cli, `${ISSUER}/bound/token`, { method: 'POST', json: { request_id: req.data.request_id } });
  assert.equal(col.status, 403);
  assert.equal(col.data.error, 'access_denied');
});

test('Flow B: wrong codes are rate-limited per session', async () => {
  const b = newBrowser();
  await registerUser(b, 'guesser');
  const { req } = await flowBRequest();
  for (let i = 0; i < 5; i++) {
    assert.equal((await b.json(ISSUER, `${ISSUER}/bound/interaction/lookup`, { user_code: `BBBB-BBB${'CDFGH'[i]}` })).status, 404);
  }
  const blocked = await b.json(ISSUER, `${ISSUER}/bound/interaction/lookup`, { user_code: req.data.user_code });
  assert.equal(blocked.status, 429, 'even the right code, until the window passes');
  assert.equal(blocked.data.error, 'slow_down');
});

// ---- M5: self-asserted device names ---------------------------------------------

test('Flow B: device names cannot pose as site addresses or hide text', async () => {
  for (const name of ['https://notebook.example', 'notebook.example/login', 'Notes‮exe.ILC', 'a\u0000b', '', ' ', 'x'.repeat(65), 42]) {
    const { req } = await flowBRequest(name);
    assert.equal(req.status, 400, JSON.stringify(name));
  }
});

test('grants say whether the client name was verified by the browser', async () => {
  const b = newBrowser();
  await registerUser(b, 'verified');
  await signIn(b);
  const { req } = await flowBRequest('Notebook');
  await b.json(ISSUER, `${ISSUER}/bound/interaction/decide`, { user_code: req.data.user_code, approve: true });
  const { data: { grants } } = await b.json(ISSUER, `${ISSUER}/api/grants`, undefined, 'GET');
  const site = grants.find((g) => g.client === RP), device = grants.find((g) => g.client === 'Notebook');
  assert.equal(site.verified, true);
  assert.equal(device.verified, false);
});

// ---- M3: consent shows how much is asked for, and for how long ---------------------

test('consent descriptions distinguish scope and state the renewal window', async () => {
  const b = newBrowser();
  const d = async (res) => (await b.json(ISSUER, `${ISSUER}/bound/describe`, { aud: [RS], grants: [{ res, act: ['read'] }] })).data;
  const all = await d(`${RS}/`), sub = await d(NOTES), one = await d(`${RS}/profile`);
  assert.equal(all.grants[0].scope, `everything at ${RS}`);
  assert.equal(sub.grants[0].scope, '/notes/ and everything under it');
  assert.equal(one.grants[0].scope, 'only /profile');
  assert.ok(all.renewHours > 0);
});

// ---- M6: the issuer's data file -----------------------------------------------------

test('a damaged issuer data file stops startup instead of being replaced', async () => {
  const file = join(dir, 'damaged.json');
  const good = await createIssuer({ origin: 'http://localhost:5609', dataFile: file, resourceServers: rsMap });
  await good.save();
  const original = await readFile(file, 'utf8');
  await writeFile(file, original.slice(0, -10));
  await assert.rejects(createIssuer({ origin: 'http://localhost:5609', dataFile: file, resourceServers: rsMap }), /Refusing to start/);
  assert.equal(await readFile(file, 'utf8'), original.slice(0, -10), 'left untouched for recovery');
  await writeFile(file, '{}');
  await assert.rejects(createIssuer({ origin: 'http://localhost:5609', dataFile: file, resourceServers: rsMap }), /Refusing to start/);
});

test('issuer saves are atomic and leave no temporary files', async () => {
  const b = newBrowser();
  await Promise.all(['save1', 'save2', 'save3'].map((u) => registerUser(newBrowser(), u)));
  await registerUser(b, 'save4');
  await issuer.save();
  const db = JSON.parse(await readFile(join(dir, 'issuer.json'), 'utf8'));
  for (const u of ['save1', 'save2', 'save3', 'save4']) assert.ok(Object.values(db.users).some((x) => x.username === u), u);
  assert.deepEqual((await readdir(dir)).filter((f) => f.endsWith('.tmp')), []);
});

// ---- M7: unauthenticated callers can't grow state without bound ----------------------

test('state that anyone can create is capped (503 busy, not unbounded memory)', async () => {
  const small = await createIssuer({ origin: 'http://localhost:5610', dataFile: join(dir, 'small.json'), resourceServers: rsMap, limits: { requests: 2, challenges: 2 } });
  await small.listen();
  servers.push(small.server);
  const cli = await makeHolder();
  const ask = () => boundFetch(cli, 'http://localhost:5610/bound/request', { method: 'POST', json: { client_name: 'x', aud: [RS], grants: [{ res: NOTES, act: ['read'] }] } });
  assert.equal((await ask()).status, 200);
  assert.equal((await ask()).status, 200);
  const third = await ask();
  assert.equal(third.status, 503);
  assert.equal(third.data.error, 'busy');
  const opt = () => fetch('http://localhost:5610/webauthn/login/options', { method: 'POST' });
  await opt(); await opt();
  assert.equal((await opt()).status, 503);

  const smallRp = await createRelyingParty({ origin: 'http://localhost:5611', issuer: ISSUER, rs: RS, maxNonces: 2 });
  await smallRp.listen();
  servers.push(smallRp.server);
  const nonce = () => fetch('http://localhost:5611/bound/nonce', { method: 'POST' });
  await nonce(); await nonce();
  assert.equal((await nonce()).status, 503);
});

// ---- M8: input validation at the issuer ----------------------------------------------

test('issuer validates display names, claims and access requests', async () => {
  const b = newBrowser();
  for (const displayName of [{ evil: true }, 'A'.repeat(65), 'Ada‮', ['x']]) {
    const r = await b.json(ISSUER, `${ISSUER}/webauthn/register/options`, { username: 'valid', displayName });
    assert.equal(r.status, 400, JSON.stringify(displayName).slice(0, 40));
  }
  await registerUser(b, 'inputs');
  const agent = await makeHolder();
  const base = { rp: RP, nonce: 'n'.repeat(20), jkt: agent.jkt };
  const bad = [
    { claims: 'username' }, { claims: { includes: 1 } }, { claims: ['email'] }, { claims: [null] },
    { access: 'x' }, { access: [] }, { access: { aud: [RS], grants: [null] } }, { access: { aud: [RS], grants: ['x'] } },
    { access: { aud: [RS], grants: [{ res: NOTES, act: ['constructor'] }] } },
    { access: { aud: [RS], grants: [{ res: NOTES, act: ['__proto__'] }] } },
    { access: { aud: ['constructor'], grants: [{ res: NOTES, act: ['read'] }] } },
    { access: { aud: [RS], grants: [{ res: `${RS}/notes%2F..%2Fadmin/`, act: ['read'] }] } },
    { access: { aud: [RS], grants: [{ res: `${NOTES}?x=1`, act: ['read'] }] } },
    { jkt: 'x'.repeat(43) + '!' }, { jkt: '!'.repeat(43) },
  ];
  for (const extra of bad) {
    const r = await b.json(ISSUER, `${ISSUER}/bound/authorize`, { ...base, ...extra });
    assert.equal(r.status, 400, JSON.stringify(extra));
  }
  const ok = await b.json(ISSUER, `${ISSUER}/bound/authorize`, { ...base, claims: ['username'] });
  assert.deepEqual(parseToken(ok.data.identity)[0].payload.claims, { username: 'inputs' }, 'only what was asked');
});

test('issuer only signs RPs in at HTTPS origins (HTTP only on loopback)', async () => {
  const b = newBrowser();
  await registerUser(b, 'rporigin');
  const agent = await makeHolder();
  const try_ = (rp) => b.json(ISSUER, `${ISSUER}/bound/authorize`, { rp, nonce: 'n'.repeat(20), jkt: agent.jkt });
  assert.equal((await try_('http://rp.example')).status, 400);
  assert.equal((await try_('null')).status, 400);
  assert.equal((await try_('https://rp.example')).status, 200);
});

// ---- L1: duplicate passkeys and usernames --------------------------------------------

test('a passkey id or username can belong to one account only', async () => {
  const victim = await registerUser(newBrowser(), 'credvictim');
  const b = newBrowser();
  const o = await b.json(ISSUER, `${ISSUER}/webauthn/register/options`, { username: 'credthief' });
  const dup = new SoftAuthenticator().create(o.data, ISSUER, { rawId: Buffer.from(victim.credential.id, 'base64url') });
  const r = await b.json(ISSUER, `${ISSUER}/webauthn/register/verify`, { challenge: o.data.challenge, credential: dup });
  assert.equal(r.status, 409);
  assert.equal(r.data.error, 'credential_exists');

  const [b1, b2] = [newBrowser(), newBrowser()];
  const [o1, o2] = [await b1.json(ISSUER, `${ISSUER}/webauthn/register/options`, { username: 'race' }), await b2.json(ISSUER, `${ISSUER}/webauthn/register/options`, { username: 'race' })];
  const v1 = await b1.json(ISSUER, `${ISSUER}/webauthn/register/verify`, { challenge: o1.data.challenge, credential: new SoftAuthenticator().create(o1.data, ISSUER) });
  const v2 = await b2.json(ISSUER, `${ISSUER}/webauthn/register/verify`, { challenge: o2.data.challenge, credential: new SoftAuthenticator().create(o2.data, ISSUER) });
  assert.deepEqual([v1.status, v2.status], [200, 409]);
});

// ---- L2: issuer outage ------------------------------------------------------------------

test('an unreachable issuer gives 503 issuer_unavailable, not a server error', async () => {
  const rs = createResourceServer({ origin: 'http://localhost:5612', issuer: 'http://localhost:5619' });
  await rs.listen();
  servers.push(rs.server);
  const agent = await makeHolder();
  const p = b64uJson({ v: 1, typ: 'bound', iss: 'http://localhost:5619', kid: 'k' });
  const r = await boundFetch(agent, 'http://localhost:5612/notes/', { token: `bnd1~${p}.AAAA` });
  assert.equal(r.status, 503);
  assert.equal(r.data.error, 'issuer_unavailable');
});

// ---- M9 / L5 / L6: renewal and revocation by the holder ------------------------------------

test('the holder can give a grant back; nobody else can', async () => {
  const b = newBrowser();
  await registerUser(b, 'giveback');
  const { agent, tokens } = await signIn(b);
  const revoke = (holder, token) => boundFetch(holder, `${ISSUER}/bound/revoke`, { method: 'POST', token });
  assert.equal((await revoke(await makeHolder(), tokens.access)).status, 401, 'not the holder');
  const delegate = await makeHolder();
  const delegated = await attenuate(tokens.access, agent, { to: delegate.jwk });
  assert.equal((await revoke(agent, delegated)).status, 401, 'the delegator no longer holds it');
  const byDelegate = await revoke(delegate, delegated);
  assert.equal(byDelegate.status, 400, 'delegates cannot revoke the grant');
  assert.equal(byDelegate.data.error, 'not_renewable');
  assert.equal((await revoke(agent, tokens.identity)).status, 401, 'identity token');
  assert.equal((await revoke(agent, tokens.access)).status, 200);
  const renew = await boundFetch(agent, `${ISSUER}/bound/renew`, { method: 'POST', token: tokens.access });
  assert.equal(renew.data.error, 'grant_revoked');
  const { data: { grants } } = await b.json(ISSUER, `${ISSUER}/api/grants`, undefined, 'GET');
  assert.equal(grants.length, 0);
});

test('identity tokens are not renewable (invalid_token)', async () => {
  const b = newBrowser();
  await registerUser(b, 'idrenew');
  const { agent, tokens } = await signIn(b, { grants: null });
  const r = await boundFetch(agent, `${ISSUER}/bound/renew`, { method: 'POST', token: tokens.identity });
  assert.equal(r.status, 401);
  assert.equal(r.data.error, 'invalid_token');
});

test('approving different access for the same client and key replaces the old grant', async () => {
  const b = newBrowser();
  await registerUser(b, 'supersede');
  const agent = await makeHolder();
  const broad = await signIn(b, { agent, grants: [{ res: `${RS}/`, act: ['read', 'write'] }] });
  await signIn(b, { agent, grants: [{ res: NOTES, act: ['read'] }] });
  const old = await boundFetch(agent, `${ISSUER}/bound/renew`, { method: 'POST', token: broad.tokens.access });
  assert.equal(old.status, 401);
  assert.equal(old.data.error, 'grant_revoked');
  const { data: { grants } } = await b.json(ISSUER, `${ISSUER}/api/grants`, undefined, 'GET');
  assert.equal(grants.length, 1);
  assert.equal(grants[0].grants[0].scope, '/notes/ and everything under it');
});
