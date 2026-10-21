// Notes API: a Bound resource server. It trusts one issuer, verifies every
// request's token + proof, and maps HTTP methods to grant actions.

import { fileURLToPath } from 'node:url';
import * as cfg from '../config.js';
import { createServer, listen, HttpError } from '../lib/http.js';
import { randomId, now } from '../lib/encoding.js';
import { ReplayCache } from '../lib/proof.js';
import { authenticate, IssuerDirectory, AuthError, wwwAuthenticate } from '../lib/verifier.js';

const ACTION = { GET: 'read', HEAD: 'read', POST: 'write', PUT: 'write', PATCH: 'write', DELETE: 'write' };

export function createResourceServer(opts = {}) {
  const origin = opts.origin ?? cfg.RS;
  const issuer = opts.issuer ?? cfg.ISSUER;
  const directory = opts.directory ?? new IssuerDirectory(issuer);
  const replay = new ReplayCache();
  const notes = new Map();   // pairwise sub -> [{id, text, created}]

  async function guard(ctx) {
    let auth;
    try {
      auth = await authenticate({
        headers: ctx.headers, method: ctx.method, url: ctx.fullUrl, body: ctx.body,
        issuer, issuerKey: directory.key, audience: origin, replay,
      });
    } catch (e) {
      if (e instanceof AuthError) throw new HttpError(e.status, e.code, e.message, e.status === 401 ? { 'www-authenticate': wwwAuthenticate(e) } : {});
      throw e;
    }
    if (!auth.token.allows(ctx.fullUrl, ACTION[ctx.method])) {
      throw new HttpError(403, 'insufficient_grant', `token does not allow ${ACTION[ctx.method]} on ${ctx.url.pathname}`);
    }
    return auth.token;
  }

  const list = (sub) => { if (!notes.has(sub)) notes.set(sub, []); return notes.get(sub); };

  const routes = [
    ['GET /notes/', async (ctx) => {
      const t = await guard(ctx);
      return { notes: list(t.sub) };
    }],
    ['POST /notes/', async (ctx) => {
      const t = await guard(ctx);
      const { text } = ctx.json();
      if (typeof text !== 'string' || !text.trim() || text.length > 500) throw new HttpError(400, 'invalid_note');
      const note = { id: randomId(8), text: text.trim(), created: now() };
      list(t.sub).push(note);
      return note;
    }],
    ['DELETE /notes/:id', async (ctx) => {
      const t = await guard(ctx);
      const l = list(t.sub);
      const i = l.findIndex((n) => n.id === ctx.params.id);
      if (i < 0) throw new HttpError(404, 'not_found');
      l.splice(i, 1);
      return { ok: true };
    }],
  ];

  // No per-address limit by default: much of an RS's traffic comes from RP
  // servers acting for many users at once, and every request needs a valid
  // token, so anonymous clients can't make it store anything.
  const server = createServer({
    origin, routes, rate: opts.rate ?? false,
    cors: () => ({
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'authorization, bound-proof, content-type',
      'access-control-allow-methods': 'GET, POST, DELETE',
      'access-control-expose-headers': 'www-authenticate',
    }),
  });
  return { server, origin, listen: () => listen(server, cfg.port(origin)) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const rs = createResourceServer();
  await rs.listen();
  console.log(`notes api ${rs.origin}`);
}
