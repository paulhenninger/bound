// Tiny HTTP toolkit for the demo servers (Node only). No framework, no deps.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { RateLimiter } from './state.js';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };

export class HttpError extends Error {
  constructor(status, code, message, headers = {}) { super(message ?? code); this.status = status; this.code = code; this.headers = headers; }
}

/** Parse a Cookie header. Never throws: malformed values are skipped. */
export function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const k = part.slice(0, i).trim();
    if (!k || k in out) continue;
    try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* malformed: ignore */ }
  }
  return out;
}

/** Set-Cookie value. `Secure` whenever the server's public origin is HTTPS. */
export function cookie(origin, name, value, maxAge) {
  const secure = new URL(origin).protocol === 'https:' ? '; Secure' : '';
  return `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

/**
 *   nonces: optional NonceIssuer; every response then carries a fresh
 *           `Bound-Nonce` header for clients to put in their next proof.
 *   rate:   per-address limit on all requests, { rate (per second), burst },
 *           or false. Endpoints add stricter limits of their own.
 */
export function createServer({ origin, routes, staticDirs = {}, cors, headers: baseHeaders = {}, nonces, rate = { rate: 50, burst: 500 } }) {
  const limiter = rate ? new RateLimiter(rate) : null;
  const handle = async (req, res) => {
    let ctx = { req, res, headers: req.headers };
    const send = (status, payload, extra = {}) => {
      if (res.headersSent) { res.end(); return; }
      const isJson = typeof payload !== 'string' && !(payload instanceof Uint8Array);
      res.writeHead(status, {
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        ...baseHeaders,
        ...(ctx.url ? cors?.(ctx) ?? {} : {}),
        ...(ctx.nonce ? { 'bound-nonce': ctx.nonce } : {}),
        ...(isJson ? { 'content-type': 'application/json' } : {}),
        ...extra,
      });
      res.end(isJson ? JSON.stringify(payload) : payload);
    };
    try {
      limiter?.take(req.socket.remoteAddress ?? 'unknown');
      const chunks = [];
      let size = 0;
      for await (const c of req) { size += c.length; if (size > 1 << 20) throw new HttpError(413, 'too_large'); chunks.push(c); }
      const body = new Uint8Array(Buffer.concat(chunks));
      let url;
      try { url = new URL(req.url, origin); } catch { throw new HttpError(400, 'invalid_request', 'bad request target'); }
      if (url.origin !== new URL(origin).origin) throw new HttpError(400, 'invalid_request', 'bad request target');
      ctx = {
        ...ctx, url, body, method: req.method, send,
        // The public URL this request was addressed to, as the client signed it.
        fullUrl: new URL(url.pathname + url.search, origin).href,
        json() {
          let v;
          try { v = JSON.parse(Buffer.from(body).toString('utf8') || '{}'); } catch { throw new HttpError(400, 'invalid_json'); }
          if (!v || typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, 'invalid_json', 'expected a JSON object');
          return v;
        },
        cookies: parseCookies(req.headers.cookie),
        nonce: nonces ? await nonces.current() : undefined,
      };
      if (req.method === 'OPTIONS' && cors) return send(204, '', {});
      for (const [pattern, handler] of routes) {
        const [m, p] = pattern.split(' ');
        if (m !== req.method) continue;
        const match = matchPath(p, url.pathname);
        if (!match) continue;
        ctx.params = match;
        const out = await handler(ctx);
        if (out !== undefined && !res.headersSent) send(200, out);
        return;
      }
      if (req.method === 'GET') {
        for (const [prefix, dir] of Object.entries(staticDirs)) {
          if (!url.pathname.startsWith(prefix)) continue;
          let rel = url.pathname.slice(prefix.length) || 'index.html';
          const file = normalize(join(dir, rel));
          if (!file.startsWith(normalize(dir) + sep) && file !== normalize(dir)) break;
          try {
            const data = await readFile(file);
            return send(200, data, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' });
          } catch { /* fall through */ }
        }
      }
      send(404, { error: 'not_found' });
    } catch (e) {
      if (e instanceof HttpError || (Number.isInteger(e?.status) && e.status >= 400 && e.status < 600)) {
        send(e.status, { error: e.code ?? 'error', error_description: e.message }, e.headers ?? {});
      } else {
        console.error(e);
        send(500, { error: 'server_error' });
      }
    }
  };
  // Last line of defence: nothing a client sends may take the process down.
  return http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      console.error(e);
      try { if (!res.headersSent) res.writeHead(500); res.end(); } catch { /* socket gone */ }
    });
  });
}

function matchPath(pattern, path) {
  const pp = pattern.split('/'), sp = path.split('/');
  if (pattern.endsWith('*')) {
    if (sp.length < pp.length - 1) return null;
  } else if (pp.length !== sp.length) return null;
  const params = {};
  for (let i = 0; i < pp.length; i++) {
    if (pp[i] === '*') { params.rest = sp.slice(i).join('/'); return params; }
    if (pp[i].startsWith(':')) {
      try { params[pp[i].slice(1)] = decodeURIComponent(sp[i]); } catch { return null; }
    }
    else if (pp[i] !== sp[i]) return null;
  }
  return params;
}

export function listen(server, port) {
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server)));
}
