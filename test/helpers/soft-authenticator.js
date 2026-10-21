// A software WebAuthn authenticator for tests. Produces the same JSON the
// issuer's passkey.js sends from a real browser.

import { generateKeyPairSync, createHash, sign, randomBytes } from 'node:crypto';

const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => createHash('sha256').update(b).digest();

export class SoftAuthenticator {
  constructor() { this.creds = []; }

  #authData(rpId, flags, counter, credId) {
    const c = Buffer.alloc(4); c.writeUInt32BE(counter);
    const parts = [sha256(rpId), Buffer.from([flags]), c];
    if (credId) {   // attested credential data: aaguid, id length, id (COSE key omitted; not parsed)
      const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
      parts.push(Buffer.alloc(16), len, credId);
    }
    return Buffer.concat(parts);
  }

  create(options, origin, { flags = 0x45, rawId = randomBytes(16) } = {}) {   // UP | UV | AT
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const id = b64u(rawId);
    const cred = { id, privateKey, rpId: options.rp.id, userHandle: options.user.id, counter: 0 };
    this.creds.push(cred);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }));
    return {
      id, type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(this.#authData(options.rp.id, flags, 0, flags & 0x40 ? rawId : null)),
        publicKey: b64u(publicKey.export({ type: 'spki', format: 'der' })),
        publicKeyAlgorithm: -7,
      },
    };
  }

  get(options, origin, { flags = 0x05, cred = this.creds[0], challenge = options.challenge, type = 'webauthn.get' } = {}) {
    cred.counter += 1;
    const clientDataJSON = Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
    const authData = this.#authData(cred.rpId, flags, cred.counter);
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), { key: cred.privateKey, dsaEncoding: 'der' });
    return {
      id: cred.id, type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData),
        signature: b64u(signature), userHandle: cred.userHandle,
      },
    };
  }
}
