// Bound uses exactly one signature algorithm: ES256 (ECDSA P-256, SHA-256),
// with signatures in IEEE P1363 (r||s, 64 bytes) form. P-256 is the curve that
// TPMs, Apple Secure Enclave, Android StrongBox and every WebCrypto implement,
// so client keys can be hardware-backed and non-exportable everywhere.

import { b64u, unb64u, utf8, sha256b64u } from './encoding.js';

const ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const SIG = { name: 'ECDSA', hash: 'SHA-256' };

/** Generate a client/issuer key pair. Client keys SHOULD be non-extractable. */
export function generateKeyPair({ extractable = false } = {}) {
  return crypto.subtle.generateKey(ALG, extractable, ['sign', 'verify']);
}

/** Export a public key as a minimal JWK: {kty, crv, x, y}. */
export async function exportPublicJwk(publicKey) {
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', publicKey);
  return { kty, crv, x, y };
}

/** Strictly validate and import a public JWK. Anything but P-256 is rejected. */
export async function importPublicJwk(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
      typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || 'd' in jwk) {
    throw new Error('unsupported key: only EC P-256 public keys are allowed');
  }
  if (unb64u(jwk.x).length !== 32 || unb64u(jwk.y).length !== 32) {
    throw new Error('invalid P-256 coordinates');
  }
  return crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true },
    ALG, true, ['verify']);
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url). Called "jkt" in Bound. */
export function thumbprint(jwk) {
  // Members in lexicographic order, no whitespace, per RFC 7638 section 3.
  return sha256b64u(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`);
}

// ECDSA signatures are malleable: if (r, s) is valid, so is (r, n - s). Bound
// signs with the low s and rejects the high one, so every signed object has
// exactly one valid encoding and its bytes can safely be hashed or compared.
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N >> 1n;
const toBig = (bytes) => bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
function fromBig(n) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}

export async function sign(privateKey, data) {
  if (typeof data === 'string') data = utf8(data);
  const sig = new Uint8Array(await crypto.subtle.sign(SIG, privateKey, data));
  const s = toBig(sig.subarray(32));
  if (s > HALF_N) sig.set(fromBig(N - s), 32);
  return b64u(sig);
}

export async function verify(publicKey, sigB64u, data) {
  if (typeof data === 'string') data = utf8(data);
  let sig;
  try { sig = unb64u(sigB64u); } catch { return false; }
  if (sig.length !== 64) return false;
  if (toBig(sig.subarray(32)) > HALF_N) return false;
  return crypto.subtle.verify(SIG, publicKey, sig, data);
}

/** Server-side persistence helpers (issuer and RP server keys only). */
export async function exportPrivateJwk(privateKey) {
  return crypto.subtle.exportKey('jwk', privateKey);
}

export async function importKeyPairJwk(privateJwk) {
  const { kty, crv, x, y, d } = privateJwk;
  const privateKey = await crypto.subtle.importKey('jwk', { kty, crv, x, y, d }, ALG, false, ['sign']);
  const publicKey = await importPublicJwk({ kty, crv, x, y });
  return { privateKey, publicKey };
}

/**
 * A "holder" bundles a key pair with its public JWK and thumbprint; it is the
 * unit that tokens are bound to and that signs proofs.
 */
export async function makeHolder(keyPair) {
  keyPair ??= await generateKeyPair();
  const jwk = await exportPublicJwk(keyPair.publicKey);
  return { ...keyPair, jwk, jkt: await thumbprint(jwk) };
}
