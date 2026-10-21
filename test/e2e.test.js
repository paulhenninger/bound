// End-to-end: real issuer, relying party and resource server over HTTP, with a
// simulated browser (cookie jar + Origin header) and a software passkey.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIssuer } from '../src/issuer/server.js';
import { createRelyingParty } from '../src/rp/server.js';
import { createResourceServer } from '../src/rs/server.js';
import { makeHolder, importKeyPairJwk, sign } from '../src/lib/keys.js';
import { b64uJson, now } from '../src/lib/encoding.js';
import { attenuate, parseToken } from '../src/lib/token.js';
import { boundFetch } from '../src/lib/client.js';
import { createProof } from '../src/lib/proof.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';
import { Browser } from './helpers/browser.js';

const ISSUER = 'http://localhost:5100';
const RP = 'http://localhost:5200';
const RS = 'http://localhost:5300';
const NOTES = `${RS}/notes/`;
const servers = [];
let dir;
let issuerHandle;

/** A browser whose issuer pages keep a device-bound session, as the real ones do. */
const newBrowser = () => new Browser({ boundOrigins: [ISSUER] });

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'bound-'));
  const rsMap = { [RS]: { name: 'Notes API', actions: { read: 'Read', write: 'Write' } } };
  const issuer = await createIssuer({ origin: ISSUER, dataFile: join(dir, 'issuer.json'), resourceServers: rsMap });
  issuerHandle = issuer;
  const rs = createResourceServer({ origin: RS, issuer: ISSUER });
  const rp = await createRelyingParty({ origin: RP, issuer: ISSUER, rs: RS });
  for (const s of [issuer, rs, rp]) { await s.listen(); servers.push(s.server); }
});
after(async () => {
  for (const s of servers) s.close();
  await rm(dir, { recursive: true, force: true });
});

async function registerUser(browser, username) {
  const auth = new SoftAuthenticator();
  const opts = await browser.json(ISSUER, `${ISSUER}/webauthn/register/options`, { username, displayName: username.toUpperCase() });
  assert.equal(opts.status, 200);
  const credential = auth.create(opts.data, ISSUER);
  const r = await browser.json(ISSUER, `${ISSUER}/webauthn/register/verify`, { challenge: opts.data.challenge, credential });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return auth;
}

/** Flow A as the mediator + RP page would run it. */
async function signIn(browser, { withAccess = true } = {}) {
  const agent = await makeHolder();
  const rpFetch = browser.fetchAs(RP);
  const cfg = await (await rpFetch(`${RP}/bound/config`)).json();
  const { data: { nonce } } = await browser.json(RP, `${RP}/bound/nonce`);
  // The mediator page (issuer origin) calls /bound/authorize with the browser-verified RP origin.
  const tokens = await browser.json(ISSUER, `${ISSUER}/bound/authorize`, {
    rp: RP, nonce, jkt: agent.jkt, claims: ['name'],
    access: withAccess ? { aud: [RS], grants: [{ res: NOTES, act: ['read', 'write'] }] } : undefined,
  });
  assert.equal(tokens.status, 200, JSON.stringify(tokens.data));
  const delegated = tokens.data.access ? await attenuate(tokens.data.access, agent, { to: cfg.serverKey }) : undefined;
  const session = await boundFetch(agent, `${RP}/bound/session`, {
    method: 'POST', token: tokens.data.identity, json: { access: delegated }, fetch: rpFetch,
  });
  return { agent, cfg, nonce, tokens: tokens.data, delegated, session, rpFetch };
}

test('Flow A: passkey sign-in, bound session, delegated API access', async () => {
  const b = newBrowser();
  await registerUser(b, 'ada');
  const { agent, session, rpFetch } = await signIn(b);
  assert.equal(session.status, 200, JSON.stringify(session.data));
  assert.equal(session.data.user.name, 'ADA');

  const me = await boundFetch(agent, `${RP}/api/me`, { fetch: rpFetch });
  assert.equal(me.status, 200);
  assert.equal(me.data.sessionKey, agent.jkt);

  const add = await boundFetch(agent, `${RP}/api/notes`, { method: 'POST', json: { text: 'hello' }, fetch: rpFetch });
  assert.equal(add.status, 200, JSON.stringify(add.data));
  const list = await boundFetch(agent, `${RP}/api/notes`, { fetch: rpFetch });
  assert.deepEqual(list.data.notes.map((n) => n.text), ['hello']);
});

test('pairwise subjects: the RP and the RS see different, stable IDs', async () => {
  const b = newBrowser();
  await registerUser(b, 'pairwise');
  const one = await signIn(b);
  const two = await signIn(b);
  assert.equal(one.session.data.user.sub, two.session.data.user.sub, 'stable per site');
  const idSub = parseToken(one.tokens.identity)[0].payload.sub;
  const accessSub = parseToken(one.tokens.access)[0].payload.sub;
  assert.notEqual(idSub, accessSub, 'unlinkable across audiences');
});

test('stolen session cookie is useless without the agent key', async () => {
  const b = newBrowser();
  await registerUser(b, 'cookie');
  const { rpFetch } = await signIn(b);
  const noProof = await rpFetch(`${RP}/api/me`);
  assert.equal(noProof.status, 401);
  const mallory = await makeHolder();
  const wrongKey = await boundFetch(mallory, `${RP}/api/me`, { fetch: rpFetch });
  assert.equal(wrongKey.status, 401);
  assert.equal(wrongKey.data.error, 'invalid_proof');
});

test('identity token: single use, audience-bound, holder-bound', async () => {
  const b = newBrowser();
  await registerUser(b, 'idtok');
  const { agent, tokens, rpFetch } = await signIn(b, { withAccess: false });
  // Replaying the same identity token (nonce consumed) fails even with the right key.
  const again = await boundFetch(agent, `${RP}/bound/session`, { method: 'POST', token: tokens.identity, json: {}, fetch: rpFetch });
  assert.equal(again.status, 400);
  assert.equal(again.data.error, 'invalid_nonce');
  // A thief who intercepted it cannot use it at all.
  const mallory = await makeHolder();
  const stolen = await boundFetch(mallory, `${RP}/bound/session`, { method: 'POST', token: tokens.identity, json: {}, fetch: rpFetch });
  assert.equal(stolen.status, 401);
  // Identity tokens are not access tokens.
  const atRs = await boundFetch(agent, NOTES, { token: tokens.identity });
  assert.equal(atRs.status, 401);
  assert.equal(atRs.data.error, 'invalid_audience');
});

test('login CSRF / session fixation: an attacker cannot plant their identity in a victim browser', async () => {
  // Attacker gets a perfectly valid identity token for their own account...
  const attacker = newBrowser();
  await registerUser(attacker, 'attacker');
  const atk = await makeHolder();
  const { data: { nonce } } = await attacker.json(RP, `${RP}/bound/nonce`);
  const t = await attacker.json(ISSUER, `${ISSUER}/bound/authorize`, { rp: RP, nonce, jkt: atk.jkt });
  // ...and makes the victim's browser submit it. The victim's page signs with the victim's key.
  const victim = newBrowser();
  const victimKey = await makeHolder();
  const r = await boundFetch(victimKey, `${RP}/bound/session`, { method: 'POST', token: t.data.identity, json: {}, fetch: victim.fetchAs(RP) });
  assert.equal(r.status, 401);
});

test('stolen access token is useless; replayed request is refused', async () => {
  const b = newBrowser();
  await registerUser(b, 'theft');
  const { agent, tokens, delegated } = await signIn(b);
  const mallory = await makeHolder();
  for (const tok of [tokens.access, delegated]) {
    const r = await boundFetch(mallory, NOTES, { token: tok });
    assert.equal(r.status, 401);
    assert.equal(r.data.error, 'invalid_proof');
  }
  // Capture a legitimate request and replay it byte for byte.
  const proof = await createProof(agent, { method: 'GET', url: NOTES, token: tokens.access });
  const headers = { authorization: `Bound ${tokens.access}`, 'bound-proof': proof };
  assert.equal((await fetch(NOTES, { headers })).status, 200);
  const replay = await fetch(NOTES, { headers });
  assert.equal(replay.status, 401);
  assert.equal((await replay.json()).error, 'replayed');
});

test('attenuation demo: worker can read, cannot write, delegator lost the token', async () => {
  const b = newBrowser();
  await registerUser(b, 'atten');
  const { agent, rpFetch } = await signIn(b);
  const r = await boundFetch(agent, `${RP}/api/attenuation-demo`, { method: 'POST', fetch: rpFetch });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.deepEqual(r.data.attempts.map((a) => a.status), [200, 403, 401]);
  assert.equal(r.data.blocks.length, 3);
});

test('renewal replaces refresh tokens; revocation stops it', async () => {
  const b = newBrowser();
  await registerUser(b, 'renew');
  const { agent, tokens, delegated } = await signIn(b);
  const renewed = await boundFetch(agent, `${ISSUER}/bound/renew`, { method: 'POST', token: tokens.access });
  assert.equal(renewed.status, 200, JSON.stringify(renewed.data));
  assert.notEqual(renewed.data.access, tokens.access);
  assert.equal((await boundFetch(agent, NOTES, { token: renewed.data.access })).status, 200);

  // Only the holder can renew, and only root tokens are renewable.
  const mallory = await makeHolder();
  assert.equal((await boundFetch(mallory, `${ISSUER}/bound/renew`, { method: 'POST', token: tokens.access })).status, 401);
  const notRoot = await boundFetch(agent, `${ISSUER}/bound/renew`, { method: 'POST', token: await attenuate(tokens.access, agent, {}) });
  assert.equal(notRoot.data.error, 'not_renewable');
  assert.ok(delegated);

  // The user revokes the grant at the issuer: renewal now fails.
  const { data: { grants } } = await b.json(ISSUER, `${ISSUER}/api/grants`, undefined, 'GET');
  const gid = parseToken(tokens.access)[0].payload.gid;
  assert.ok(grants.some((g) => g.gid === gid));
  assert.equal((await b.json(ISSUER, `${ISSUER}/api/grants/${gid}/revoke`, {})).status, 200);
  const dead = await boundFetch(agent, `${ISSUER}/bound/renew`, { method: 'POST', token: renewed.data.access });
  assert.equal(dead.status, 401);
  assert.equal(dead.data.error, 'grant_revoked');
});

test('expired tokens are refused by the RS but renewable by their holder', async () => {
  const b = newBrowser();
  await registerUser(b, 'expired');
  const { agent, tokens } = await signIn(b);
  // Re-sign the user's real access token as if it had been issued 20 minutes ago.
  const root = parseToken(tokens.access)[0].payload;
  const { privateKey } = await importKeyPairJwk(issuerHandle.db.key);
  const old = { ...root, iat: now() - 1200, exp: now() - 900 };
  const p = b64uJson(old);
  const expired = `bnd1~${p}.${await sign(privateKey, p)}`;
  const atRs = await boundFetch(agent, NOTES, { token: expired });
  assert.equal(atRs.status, 401);
  assert.equal(atRs.data.error, 'expired');
  const renewed = await boundFetch(agent, `${ISSUER}/bound/renew`, { method: 'POST', token: expired });
  assert.equal(renewed.status, 200, JSON.stringify(renewed.data));
  assert.equal((await boundFetch(agent, NOTES, { token: renewed.data.access })).status, 200);
});

test('Flow B: back-channel request approved by the user on another device', async () => {
  const b = newBrowser();
  await registerUser(b, 'device');
  const cli = await makeHolder();
  const req = await boundFetch(cli, `${ISSUER}/bound/request`, {
    method: 'POST', json: { client_name: 'Test CLI', aud: [RS], grants: [{ res: NOTES, act: ['read'] }] },
  });
  assert.equal(req.status, 200, JSON.stringify(req.data));
  const poll = () => boundFetch(cli, `${ISSUER}/bound/token`, { method: 'POST', json: { request_id: req.data.request_id } });
  assert.equal((await poll()).status, 428);

  // Someone who learns the request_id cannot collect it with their own key.
  const mallory = await makeHolder();
  const steal = await boundFetch(mallory, `${ISSUER}/bound/token`, { method: 'POST', json: { request_id: req.data.request_id } });
  assert.equal(steal.status, 400);

  const look = await b.json(ISSUER, `${ISSUER}/bound/interaction/lookup`, { user_code: req.data.user_code.toLowerCase() });
  assert.equal(look.data.client_name, 'Test CLI');
  await b.json(ISSUER, `${ISSUER}/bound/interaction/decide`, { user_code: req.data.user_code, approve: true });

  const tok = await poll();
  assert.equal(tok.status, 200);
  assert.equal((await boundFetch(cli, NOTES, { token: tok.data.access })).status, 200);
  const write = await boundFetch(cli, NOTES, { method: 'POST', token: tok.data.access, json: { text: 'x' } });
  assert.equal(write.status, 403);
  assert.equal((await poll()).status, 400, 'results are collected once');
});

test('issuer refuses cross-origin and unauthenticated authorize calls', async () => {
  const b = newBrowser();
  await registerUser(b, 'csrf');
  const agent = await makeHolder();
  const body = { rp: RP, nonce: 'n'.repeat(20), jkt: agent.jkt };
  const evil = await b.json('https://evil.example', `${ISSUER}/bound/authorize`, body);
  assert.equal(evil.status, 403);
  const anon = await newBrowser().json(ISSUER, `${ISSUER}/bound/authorize`, body);
  assert.equal(anon.status, 401);
});

test('issuer refuses grants outside the resource server or with unknown actions', async () => {
  const b = newBrowser();
  await registerUser(b, 'scope');
  const agent = await makeHolder();
  const base = { rp: RP, nonce: 'n'.repeat(20), jkt: agent.jkt };
  const outside = await b.json(ISSUER, `${ISSUER}/bound/authorize`, { ...base, access: { aud: [RS], grants: [{ res: 'https://evil.example/', act: ['read'] }] } });
  assert.equal(outside.status, 400);
  const badAct = await b.json(ISSUER, `${ISSUER}/bound/authorize`, { ...base, access: { aud: [RS], grants: [{ res: NOTES, act: ['admin'] }] } });
  assert.equal(badAct.status, 400);
});

test('issuer metadata is minimal and fixed', async () => {
  const md = await (await fetch(`${ISSUER}/.well-known/bound-issuer`)).json();
  assert.equal(md.alg, 'ES256');
  assert.equal(md.keys.length, 1);
  assert.ok(!('d' in md.keys[0]));
});
