import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyRegistration, verifyAssertion, WebAuthnError } from '../src/lib/webauthn.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';

const ORIGIN = 'https://id.example';
const RPID = 'id.example';
const regOpts = { challenge: 'Y2hhbGxlbmdlLXJlZ2lzdHJhdGlvbi0x', rp: { id: RPID }, user: { id: 'dXNlcjE' } };
const getOpts = { challenge: 'Y2hhbGxlbmdlLWxvZ2luLTAwMDAwMDE' };

async function registered() {
  const a = new SoftAuthenticator();
  const credential = a.create(regOpts, ORIGIN);
  const stored = await verifyRegistration({ credential, expectedChallenge: regOpts.challenge, expectedOrigin: ORIGIN, rpId: RPID });
  return { a, stored };
}
const login = (a, stored, o = {}) => verifyAssertion({
  credential: a.get(getOpts, o.origin ?? ORIGIN, o), stored,
  expectedChallenge: getOpts.challenge, expectedOrigin: ORIGIN, rpId: RPID,
});

test('register then sign in with a passkey', async () => {
  const { a, stored } = await registered();
  const { signCount } = await login(a, stored);
  assert.equal(signCount, 1);
});

test('phishing origin is rejected (the core passkey property)', async () => {
  const { a, stored } = await registered();
  await assert.rejects(login(a, stored, { origin: 'https://id-example.evil' }), WebAuthnError);
});

test('wrong challenge, wrong ceremony type, missing UV are rejected', async () => {
  const { a, stored } = await registered();
  await assert.rejects(login(a, stored, { challenge: 'b3RoZXI' }), /challenge/);
  await assert.rejects(login(a, stored, { type: 'webauthn.create' }), /ceremony/);
  await assert.rejects(login(a, stored, { flags: 0x01 }), /not verified/);
});

test('cloned authenticator (non-increasing counter) is detected', async () => {
  const { a, stored } = await registered();
  const first = await login(a, stored);
  stored.signCount = first.signCount + 5;
  await assert.rejects(login(a, stored), /counter/);
});

test('signature from another key fails', async () => {
  const { stored } = await registered();
  const other = new SoftAuthenticator();
  other.create(regOpts, ORIGIN);
  other.creds[0].id = stored.credentialId;   // claim the victim's credential id
  await assert.rejects(login(other, stored), /signature/);
});
