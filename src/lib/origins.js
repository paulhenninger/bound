// Which origins may sign in with Bound (shared by the issuer server and its
// mediator page, so both apply the same rule).

const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'];

/** RP origins must be HTTPS. Plain HTTP is allowed only on loopback, for development. */
export function isAllowedRpOrigin(rp) {
  if (typeof rp !== 'string') return false;
  let u;
  try { u = new URL(rp); } catch { return false; }
  if (u.origin !== rp) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && LOOPBACK.includes(u.hostname);
}
