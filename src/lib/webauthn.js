// Minimal, dependency-free WebAuthn (passkey) verification for ES256 credentials.
// Attestation is not verified ("none"); Bound relies on passkeys for phishing
// resistance and user verification, not for authenticator provenance.

import { unb64u, fromUtf8, sha256, concat, timingSafeEqual } from './encoding.js';

const ES256 = -7;
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

export class WebAuthnError extends Error {}
const fail = (m) => { throw new WebAuthnError(m); };

function checkClientData(clientDataJSON, type, expectedChallenge, expectedOrigin) {
  let cd;
  try { cd = JSON.parse(fromUtf8(unb64u(clientDataJSON))); } catch { fail('bad clientDataJSON'); }
  if (cd.type !== type) fail('wrong ceremony type');
  if (!timingSafeEqual(cd.challenge ?? '', expectedChallenge)) fail('challenge mismatch');
  if (cd.origin !== expectedOrigin) fail('origin mismatch');
  if (cd.crossOrigin === true) fail('cross-origin ceremony not allowed');
}

async function parseAuthData(authenticatorData, rpId) {
  const ad = unb64u(authenticatorData);
  if (ad.length < 37) fail('authenticatorData too short');
  if (!timingSafeEqual(ad.subarray(0, 32), await sha256(rpId))) fail('rpId mismatch');
  const flags = ad[32];
  if (!(flags & FLAG_UP)) fail('user not present');
  if (!(flags & FLAG_UV)) fail('user not verified');
  const signCount = ((ad[33] << 24) | (ad[34] << 16) | (ad[35] << 8) | ad[36]) >>> 0;
  return { ad, flags, signCount };
}

/** Credential ID from the attested credential data (registration only). */
function attestedCredentialId(ad, flags) {
  if (!(flags & FLAG_AT)) fail('no attested credential data');
  // rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId(L) ...
  if (ad.length < 55) fail('attested credential data too short');
  const len = (ad[53] << 8) | ad[54];
  if (len < 1 || len > 1023 || ad.length < 55 + len) fail('bad credential id length');
  return ad.subarray(55, 55 + len);
}

/** Convert an ASN.1 DER ECDSA signature to IEEE P1363 (r||s) for WebCrypto. */
export function derToP1363(der) {
  let i = 0;
  const expect = (tag) => { if (der[i++] !== tag) fail('bad DER signature'); };
  const readLen = () => {
    let len = der[i++];
    if (len & 0x80) { const n = len & 0x7f; len = 0; for (let k = 0; k < n; k++) len = (len << 8) | der[i++]; }
    return len;
  };
  const readInt = () => {
    expect(0x02);
    let len = readLen();
    let v = der.subarray(i, i + len); i += len;
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) fail('bad DER integer');
    const out = new Uint8Array(32); out.set(v, 32 - v.length); return out;
  };
  expect(0x30); readLen();
  const r = readInt(); const s = readInt();
  if (i !== der.length) fail('trailing DER data');
  return concat(r, s);
}

/**
 * Verify a registration (navigator.credentials.create) response. The browser
 * hands us the SPKI public key via response.getPublicKey(), so no CBOR parsing.
 */
export async function verifyRegistration({ credential, expectedChallenge, expectedOrigin, rpId }) {
  const r = credential.response;
  if (credential.type !== 'public-key') fail('wrong credential type');
  if (r.publicKeyAlgorithm !== ES256) fail('only ES256 passkeys are supported');
  if (typeof credential.id !== 'string' || !credential.id || credential.id.length > 1400) fail('bad credential id');
  checkClientData(r.clientDataJSON, 'webauthn.create', expectedChallenge, expectedOrigin);
  const { ad, flags, signCount } = await parseAuthData(r.authenticatorData, rpId);
  // The id the client reports must be the one the authenticator created.
  let claimed;
  try { claimed = unb64u(credential.id); } catch { fail('bad credential id'); }
  if (!timingSafeEqual(claimed, attestedCredentialId(ad, flags))) fail('credential id does not match authenticator data');
  // Make sure the key is importable now rather than at first login.
  await crypto.subtle.importKey('spki', unb64u(r.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  return { credentialId: credential.id, publicKey: r.publicKey, signCount };
}

/** Verify an authentication (navigator.credentials.get) response. */
export async function verifyAssertion({ credential, stored, expectedChallenge, expectedOrigin, rpId }) {
  const r = credential.response;
  if (credential.type !== 'public-key') fail('wrong credential type');
  if (credential.id !== stored.credentialId) fail('unknown credential');
  checkClientData(r.clientDataJSON, 'webauthn.get', expectedChallenge, expectedOrigin);
  const { ad, signCount } = await parseAuthData(r.authenticatorData, rpId);
  const key = await crypto.subtle.importKey('spki', unb64u(stored.publicKey),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const signed = concat(ad, await sha256(unb64u(r.clientDataJSON)));
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key,
    derToP1363(unb64u(r.signature)), signed);
  if (!ok) fail('bad assertion signature');
  // A non-zero counter that fails to increase suggests a cloned authenticator.
  if (signCount !== 0 && signCount <= stored.signCount) fail('signature counter did not increase');
  return { signCount };
}
