# Bound

[![Tests](https://github.com/paulhenninger/bound/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/paulhenninger/bound/actions/workflows/test.yml)

**A key-bound, browser-mediated alternative to OAuth 2.0 + OpenID Connect.**
This repository contains a specification and a working, dependency-free reference
implementation.

- **[SPEC.md](SPEC.md)**: the protocol: token format, proofs, flows, threat model.
- **[docs/oauth-oidc-analysis.md](docs/oauth-oidc-analysis.md)**: why: an analysis of
  where OAuth 2.0 + OIDC's complexity and weaknesses come from, what the industry is doing
  about it, and practical recommendations for today.

> ⚠️ Bound is a design exercise. It has not been reviewed or formally analyzed. Read it,
> run it, argue with it, but don't put it in production.

## The idea in one paragraph

Nothing is a bearer token. Every token is bound to a non-exportable key, and every
request is signed over its method, URL, body and token. So a token copied from a log, a
URL or storage is inert. Sign-in is mediated by the browser, which authenticates both
origins, so there are no redirects to attack. Tokens are chains of signed blocks: the
holder can narrow a token and delegate it to another key offline, and nobody can widen
it. Tokens live for minutes and are renewed by proving possession of the key, so there
are no refresh tokens. There is one algorithm (ES256), one token format and one proof
format, so there is nothing to negotiate.

## What's in the demo

Three separate origins, as in a real deployment:

| Origin | Role | What it does |
|---|---|---|
| `http://localhost:4100` | **Bound ID**, the issuer | Passkey-only accounts, consent, grants list with revoke, token minting, renewal, device approval |
| `http://localhost:4200` | **Notebook**, a relying party | "Sign in with Bound ID" popup, bound session, notes UI, attenuation demo |
| `http://localhost:4300` | **Notes API**, a resource server | Verifies token + proof on every request, enforces grants |

Plus a **CLI client** that uses Flow B (back-channel approval with a user code).

## Running it

Requires Node.js 22 or later. There are no dependencies to install.

```bash
npm start
```

Then open http://localhost:4200 in a browser with passkey support (Chrome, Edge,
Safari, Firefox). Windows Hello, Touch ID, a phone or a security key will work.

1. **Sign in with Bound ID.** A popup opens at the issuer. Create an account with a
   passkey and approve. The popup shows Notebook's origin, which the browser verified.
2. Notebook now shows your **pairwise ID** and your **session key thumbprint**. Click
   **Replay my cookie without the key**: the server refuses the bare cookie.
3. **Add notes.** Notebook's server calls the Notes API with a token your browser
   *delegated* to the server's key.
4. **Attenuation & delegation → Run it.** The server derives a read-only, 60-second
   token for a worker. The worker can read (200), can't write (403), and the server can no
   longer use the token it gave away (401). Expand *Token blocks* to see the chain.
5. Open http://localhost:4100 to see the **grant**, and revoke it. Within one token
   lifetime Notebook can no longer renew access. Signing out of Notebook also gives the
   grant back and replaces the browser's key.

Use exactly `localhost` (not `127.0.0.1`): origins and passkeys are bound to the exact
address, and the pages tell you if you are on the wrong one.

The CLI, in another terminal:

```bash
npm run cli -- "note from the terminal"
```

It prints a code. Open http://localhost:4100/device.html, type the code and approve.
The CLI keeps its key and token in `~/.bound/notes-cli.json` (override with
`BOUND_CLI_STATE`), so later runs renew without asking again. `npm run cli -- --forget`
revokes the grant and deletes the file.

Issuer state (signing key, accounts and grants) is kept in `data/issuer.json`, written
atomically. If the file is damaged the issuer refuses to start rather than replace it.
Delete it to start fresh, and delete the matching passkey from your authenticator too.

## Tests

```bash
npm test
```

79 tests, using Node's built-in runner. They include a software WebAuthn authenticator,
run the three servers over real HTTP with a simulated browser, and drive the mediator
popup's and RP page's `postMessage` handling with fake windows. Besides the happy paths
(both flows, delegation, renewal, revocation), they exercise attacks:

- stolen access, identity and delegated tokens used with another key
- byte-for-byte request replay
- stolen session cookie without the agent key
- login CSRF (planting the attacker's identity token in a victim browser)
- forged attenuation and delegation blocks; blocks spliced between tokens
- widening grants via attenuation; tampered root claims
- phishing origins, wrong challenges, missing user verification and cloned
  authenticators for passkeys
- cross-origin calls to issuer endpoints; out-of-scope grant requests
- collecting someone else's Flow B result, or one whose grant was revoked after approval
- proofs pre-signed for later use (server nonces), high-S signature twins
- grant escapes through encoded slashes (`/notes/..%2Fadmin`)
- malformed cookies, paths and request targets (must never crash a server)
- floods of challenges, nonces and Flow B requests (bounded, `503 busy`)
- forged `postMessage` sources and origins, plain-HTTP RP origins, consent clickjacking
- device names posing as site addresses; Flow B code guessing (rate-limited)
- malformed claims, display names and grants (`act: ["constructor"]`)
- duplicate passkey IDs and usernames; a damaged issuer data file; issuer outages

## Contributing

Attacks, spec problems and bug reports are the most useful contributions. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules and how the tests are organized.

## Layout

```
SPEC.md                         the protocol
docs/oauth-oidc-analysis.md     the motivation
src/lib/                        isomorphic library (Node + browser, WebCrypto only)
  keys.js        ES256 keys (low-S signatures), JWK, thumbprints
  token.js       Bound Tokens: issue, attenuate/delegate, verify, authorize
  proof.js       Bound-Proof: create, verify, replay cache, server nonces
  verifier.js    resource-server request authentication, issuer key discovery
  client.js      boundFetch(): requests with token + proof
  agent.js       browser: non-exportable agent key, mediator popup (Flow A polyfill)
  webauthn.js    passkey verification (ES256, no CBOR needed)
  http.js        tiny HTTP server helpers for the demo
  state.js       bounded, self-expiring in-memory maps
  origins.js     which RP origins may sign in
src/issuer/     issuer server + pages (account, mediator popup, device approval)
src/rp/         relying party server + Notebook page
src/rs/         Notes API resource server
src/cli/        Flow B command-line client
test/           unit and end-to-end tests
```

## Demo shortcuts (not part of the protocol)

- **Plain HTTP on localhost.** Browsers treat `localhost` as a secure context, so passkeys
  and WebCrypto work. Production requires HTTPS; the issuer only accepts plain-HTTP RP
  origins on loopback, and cookies get `Secure` automatically on HTTPS origins.
- **Cookie names differ per server** (`bound_idp`, `rp_sid`) because browsers don't
  isolate cookies by port on the same host.
- **In-memory state** for sessions, notes and pending requests (bounded and
  self-expiring). Restarting logs everyone out. The issuer's keys, accounts and grants
  persist.
- **Flow A uses the popup polyfill** (SPEC §8.2), since no browser implements the native
  API (§8.1).
