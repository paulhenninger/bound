// Isomorphic encoding helpers (Node >= 20 and modern browsers).

const enc = new TextEncoder();
const dec = new TextDecoder();

export const utf8 = (s) => enc.encode(s);
export const fromUtf8 = (b) => dec.decode(b);

export function b64u(bytes) {
  if (typeof bytes === 'string') bytes = utf8(bytes);
  bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64u(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('invalid base64url');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const b64uJson = (obj) => b64u(utf8(JSON.stringify(obj)));
export const unb64uJson = (s) => JSON.parse(fromUtf8(unb64u(s)));

export async function sha256(data) {
  if (typeof data === 'string') data = utf8(data);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export const sha256b64u = async (data) => b64u(await sha256(data));

export function randomId(bytes = 16) {
  return b64u(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

export function timingSafeEqual(a, b) {
  if (typeof a === 'string') a = utf8(a);
  if (typeof b === 'string') b = utf8(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export const now = () => Math.floor(Date.now() / 1000);
