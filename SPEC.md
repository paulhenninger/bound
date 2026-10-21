# Bound: Key-Bound, Browser-Mediated Authentication and Authorization

**Version:** 1 (draft 0.3)
**Status:** Experimental design. Not reviewed, not formally analyzed. Do not deploy.
**Reference implementation:** [`src/`](src/) in this repository.
**Background:** [docs/oauth-oidc-analysis.md](docs/oauth-oidc-analysis.md) explains why this exists.

---

## Abstract

Bound is a single protocol for the jobs OAuth 2.0 and OpenID Connect do together:
federated sign-in, and delegated access to APIs. It differs from them in five ways:

1. **Every token is bound to a key, and every use of a token is signed.** There are no
   bearer tokens. A token copied from a log, a URL, storage or the network is inert.
2. **The browser mediates sign-in.** Tokens never travel in URLs. The browser
   authenticates the origin of the requesting site and delivers tokens only to that origin.
3. **There is one algorithm, one token format and one proof format.** There is nothing
   to negotiate, so nothing to downgrade.
4. **Tokens are capabilities.** The holder can narrow one and hand it to another key
   offline, without asking the issuer. Nobody can widen one.
5. **Renewal replaces refresh tokens.** Tokens live for minutes. The holder renews by
   proving possession again, and the issuer re-checks the grant every time.

---

## Table of contents

1. [Conventions and terminology](#1-conventions-and-terminology)
2. [Overview](#2-overview)
3. [Cryptography](#3-cryptography)
4. [Issuer metadata](#4-issuer-metadata)
5. [Bound Tokens](#5-bound-tokens)
6. [Bound-Proof](#6-bound-proof)
7. [Presenting a token to a resource server](#7-presenting-a-token-to-a-resource-server)
8. [Flow A: browser-mediated sign-in](#8-flow-a-browser-mediated-sign-in)
9. [Bound sessions](#9-bound-sessions)
10. [Flow B: back-channel authorization](#10-flow-b-back-channel-authorization)
11. [Attenuation and delegation](#11-attenuation-and-delegation)
12. [Renewal and revocation](#12-renewal-and-revocation)
13. [User authentication at the issuer](#13-user-authentication-at-the-issuer)
14. [Errors](#14-errors)
15. [Security considerations](#15-security-considerations)
16. [Privacy considerations](#16-privacy-considerations)
17. [Relationship to existing standards](#17-relationship-to-existing-standards)
18. [Open issues](#18-open-issues)
19. [Appendix A: worked example](#appendix-a-worked-example)

---

## 1. Conventions and terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when they appear in capitals.

| Term | Meaning |
|---|---|
| **User** | The person signing in and granting access. |
| **Issuer** | The service that authenticates users and issues tokens. It combines the roles of OIDC's OpenID Provider and OAuth's Authorization Server. Identified by an origin, e.g. `https://id.example`. |
| **Relying Party (RP)** | A website that signs users in with an issuer. Identified by its origin. |
| **Resource Server (RS)** | An API that accepts Bound tokens. Identified by its origin. |
| **Client** | Any software that holds a key and uses tokens: an RP's browser page, an RP's server, a CLI, a background worker. |
| **Agent key** | A non-exportable key held by the user's browser for one RP origin. |
| **Holder** | The key a token is currently bound to. Only the holder can use, narrow, delegate or renew the token. |
| **jkt** | The JWK SHA-256 thumbprint of a public key (RFC 7638), base64url-encoded. 43 characters. |
| **Grant** | A user's standing decision to let one client key access one resource server with given permissions. The issuer stores it; tokens refer to it by `gid`. |
| **b64u** | base64url without padding (RFC 4648 §5). |
| **now** | Current time in integer seconds since the Unix epoch. |

---

## 2. Overview

```
                ┌────────────── Issuer (id.example) ───────────────┐
                │  passkey login · consent · grants · signing key  │
                └───────▲──────────────────▲─────────────────▲─────┘
       (A) mediator     │  (B) request /    │   renew         │ keys (/.well-known)
       popup / browser  │      token        │   (proof)       │
                ┌───────┴───────┐   ┌───────┴──────┐   ┌──────┴────────┐
  User ───────▶ │ Browser + RP  │   │ CLI / device │   │ Resource      │
                │ page          │   │ client       │   │ Server (API)  │
                │ agent key     │   │ client key   │   │ verifies      │
                └───────┬───────┘   └──────┬───────┘   │ token + proof │
                        │ delegate         │           └──────▲────────┘
                ┌───────▼───────┐          │                  │
                │ RP server     │──────────┴──────────────────┘
                │ server key    │   Authorization: Bound <token>
                └───────────────┘   Bound-Proof: <signed request digest>
```

**Flow A, browser sign-in (replaces OIDC + the OAuth code flow):**

1. The RP page creates (once) a non-exportable **agent key** and gets a fresh nonce from
   its server.
2. The page asks the browser to contact the issuer. The browser tells the issuer the RP's
   true origin.
3. The user authenticates at the issuer with a passkey and approves.
4. The issuer returns an **identity token** (and optionally an **access token**), both
   bound to the agent key. The browser delivers them only to the RP origin.
5. The page presents the identity token to its server with a proof signed by the agent
   key. The server creates a **bound session**.
6. If the RP server needs API access, the page **delegates** the access token to the RP
   server's key by appending a block.

**Flow B, back-channel (replaces the device grant and other non-browser grants):**

1. A client with its own key sends a signed request to the issuer and gets a user code.
2. The user enters the code at the issuer on any device and approves.
3. The client collects the token. Only the key that made the request can collect it.

**Using a token:** every API request carries the token and a fresh `Bound-Proof` signed
by the holder over the method, URL, body and token.

---

## 3. Cryptography

### 3.1 One algorithm

All signatures in Bound, from issuers, clients, proofs and attenuation blocks, **MUST** be
**ES256**: ECDSA using P-256 and SHA-256. Signatures are encoded in IEEE P1363 form
(32-byte `r` ‖ 32-byte `s`, 64 bytes total) and then b64u-encoded.

ECDSA signatures are malleable: if (`r`, `s`) is valid, so is (`r`, n − `s`). Signers
**MUST** produce the low form (`s` ≤ n/2, normalizing if their library does not) and
verifiers **MUST** reject the high form. Every signed object then has exactly one valid
encoding, so hashes of signatures (`prev`, §5.3) and of tokens (`ath`, §6.1) identify them.

There is no `alg` field anywhere. Implementations **MUST** reject keys of any other type
or curve. This removes the algorithm confusion attacks (e.g. `alg: none`, or an HMAC
"signature" checked with a public key) seen in JOSE deployments.

*Rationale:* P-256 is the only curve available in essentially every secure key store:
TPM 2.0, Apple Secure Enclave, Android StrongBox and Keystore, and WebCrypto in every
browser. Client keys can therefore always be hardware-backed and non-exportable. Ed25519
would be preferable on purely technical grounds, but it is not universally available in
hardware.

### 3.2 Keys

Public keys are represented as JWKs (RFC 7517) with the members `kty` = `"EC"`,
`crv` = `"P-256"`, and `x` and `y` (each exactly 32 bytes, b64u). Only these four members
determine the key and its thumbprint. Other members are ignored, which lets issuer
metadata (§4) carry `kid`, `alg` and `use`. Clients **SHOULD** send only the four. A JWK
containing `d` **MUST** be rejected wherever a public key is expected.

Clients **SHOULD** generate keys as non-extractable: WebCrypto `extractable: false`
stored in IndexedDB, or OS key stores.

### 3.3 Thumbprints

`jkt(jwk)` = b64u(SHA-256(`{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}`)), with
members in that order and no whitespace, as in RFC 7638.

### 3.4 Signed objects

Tokens and proofs use the same construction:

```
signed = b64u(UTF8(JSON(payload))) "." b64u(ES256(key, ASCII(b64u(UTF8(JSON(payload))))))
```

The verifier checks the signature over the received b64u string and only then parses
the JSON. No canonicalization is required.

---

## 4. Issuer metadata

An issuer **MUST** publish metadata at `GET <issuer>/.well-known/bound-issuer`:

```json
{
  "issuer": "https://id.example",
  "version": 1,
  "alg": "ES256",
  "keys": [{ "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "k7Qd2mVbX4o", "alg": "ES256", "use": "sig" }],
  "mediator": "https://id.example/bound/mediator.html",
  "request_endpoint": "https://id.example/bound/request",
  "token_endpoint": "https://id.example/bound/token",
  "renew_endpoint": "https://id.example/bound/renew",
  "revoke_endpoint": "https://id.example/bound/revoke",
  "interaction": "https://id.example/device.html"
}
```

- `issuer` **MUST** equal the origin the metadata was fetched from. Verifiers **MUST**
  reject a mismatch.
- `keys` lists the current signing keys, each with a `kid`. To rotate, publish the new
  key alongside the old one, start signing with the new key, and remove the old key once
  every token signed with it has expired and its renewal window has closed. (The reference
  issuer does this with `npm run rotate-key`.)
- Verifiers **SHOULD** cache keys and refetch when they see an unknown `kid`, at most
  once every 30 seconds, with one fetch in flight at a time. If the issuer cannot be
  reached they **SHOULD** back off for a few seconds and answer `503`
  `issuer_unavailable` rather than treating the token as invalid.

The metadata is served with `Access-Control-Allow-Origin: *` because it is public.

---

## 5. Bound Tokens

### 5.1 Encoding

```
token = "bnd1" 1*8( "~" block )
block = signed-object              ; §3.4
```

- `bnd1` identifies version 1 of the format.
- A token has **1 to 8 blocks**. Block 0 is the **root block**, signed by the issuer.
  Blocks 1 and later are **attenuation blocks**, each signed by the token's holder at
  the time it was added.
- A token **MUST NOT** exceed 16384 characters.
- The token's character set is `[A-Za-z0-9_.~-]`, so it fits in an HTTP header without
  escaping.

### 5.2 Root block

| Claim | Type | Req. | Meaning |
|---|---|---|---|
| `v` | int | ✓ | `1` |
| `typ` | string | ✓ | `"bound"` |
| `iss` | string | ✓ | Issuer origin |
| `kid` | string | ✓ | Issuer key ID |
| `jti` | string | ✓ | Unique token ID (≥ 128 bits random) |
| `iat` | int | ✓ | Issued at |
| `exp` | int | ✓ | Expires at. Access tokens **SHOULD** live ≤ 300 s; identity tokens ≤ 120 s. |
| `sub` | string | ✓ | Subject, **pairwise** per audience (§16) |
| `aud` | string[] | ✓ | Origins the token may be presented to |
| `cnf` | object | ✓ | `{ "jkt": <thumbprint> }`, the initial holder |
| `grants` | object[] | ✓ | Permissions (§5.5). An empty array means an **identity token**: proof of who the user is, with no API access. |
| `nonce` | string | identity | Echo of the RP's nonce (§8) |
| `claims` | object | – | Released user attributes, e.g. `{ "name": "Ada" }` |
| `gid` | string | access | ID of the grant this token was minted from (§12) |
| `rex` | int | access | Renewal expiry: the token can be renewed until this time (§12) |

Verifiers **MUST** ignore unknown claims.

### 5.3 Attenuation block

| Claim | Type | Req. | Meaning |
|---|---|---|---|
| `prev` | string | ✓ | b64u(SHA-256(ASCII(signature part of the previous block))) |
| `iat` | int | ✓ | When the block was added |
| `by` | JWK | ✓ | Public key of the signer. It **MUST** be the current holder. |
| `exp` | int | – | A tighter expiry |
| `aud` | string[] | – | A tighter audience |
| `grants` | object[] | – | A tighter set of permissions |
| `cnf` | object | – | `{ "jkt": … }`: **delegate** the token to a new holder |

`prev` chains each block to the exact previous block, so blocks cannot be moved between
tokens. Because each block must be signed by the current holder, **someone who copies a
token can neither narrow it nor delegate it**. Every change to a token requires the key.

### 5.4 Verification algorithm

Given a token string `T`, the expected issuer `I`, the verifier's own origin `A`, and a
function `key(iss, kid)`:

1. Split `T` on `~`. The first part **MUST** be `bnd1`; there **MUST** be 1–8 blocks;
   each block **MUST** have exactly two `.`-separated parts.
2. **Root:** decode the payload. Require `v == 1`, `typ == "bound"`, `iss == I`. Look
   up `key(iss, kid)`; fail if absent. Verify the signature. Require `sub`, `aud`,
   `cnf.jkt`, `grants`, `iat` and `exp` with the types in §5.2.
3. Set `holder := root.cnf.jkt`, `exp := root.exp`, `grantSets := [root.grants]`.
4. For each attenuation block `i` in order:
   1. Require `prev == b64u(SHA-256(sig_{i-1}))`.
   2. Import `by` (§3.2). Require `jkt(by) == holder`. Verify the block's signature with `by`.
   3. Require integer `iat ≥ root.iat`.
   4. If `exp` is present: `exp := min(exp, block.exp)`.
   5. If `grants` is present: append it to `grantSets`.
   6. If `cnf` is present: `holder := block.cnf.jkt`.
5. Require `root.iat ≤ now + 60` and `now < exp + 60` (60 seconds of clock skew).
6. For **every** block that has `aud`, require `A ∈ aud`.
7. The result is `(sub, holder, exp, grantSets, root claims)`.

A valid token authorizes nothing by itself. The caller **MUST** also verify a proof by
`holder` (§6) and check the grants (§5.5).

### 5.5 Grants and authorization

```json
{ "res": "https://notes.example/notes/", "act": ["read", "write"] }
```

- `res` is an absolute URL. If its path ends in `/`, it matches that path and everything
  below it. Otherwise it matches that exact path. Origins must match exactly. Query
  strings are ignored for matching.
- `act` is a list of actions. The resource server defines its action names and how
  requests map to them. The reference RS maps GET/HEAD to `read` and
  POST/PUT/PATCH/DELETE to `write`.
- Request URLs are parsed with the WHATWG URL parser, which removes dot segments
  (including `%2e%2e`), before matching.
- A request path containing an encoded `/` or `\` (`%2F`, `%5C`, any case) **MUST NOT**
  match any grant. Matching works on the encoded path, but many servers decode before
  routing, and `/notes/..%2Fadmin` would then match a `/notes/` grant yet reach `/admin`.
  For the same reason the issuer **MUST** refuse grants whose `res` contains them, or has a
  query, fragment or userinfo.

**A request for action `a` on URL `u` is authorized if and only if every grant set in
`grantSets` contains at least one grant matching `(u, a)`.**

So attenuation can only narrow permissions. A block that lists broader grants than its
predecessors has no effect beyond the intersection. The issuer does not need to police
attenuations.

Grants are deliberately simple. Richer conditions (time-of-day, IP range, amount limits)
are out of scope for v1 and listed in §18.

---

## 6. Bound-Proof

Every request that uses a token, a bound session (§9), or a Flow B endpoint carries a
**proof**: a signed statement by a key about exactly this request.

### 6.1 Format

`Bound-Proof: <signed-object>` (§3.4), with payload:

| Claim | Req. | Meaning |
|---|---|---|
| `typ` | ✓ | `"bound-proof"` |
| `jwk` | ✓ | Public key of the signer |
| `htm` | ✓ | HTTP method, uppercase |
| `htu` | ✓ | Absolute request URL **including the query string**, without the fragment, as serialized by the WHATWG URL parser |
| `iat` | ✓ | Creation time |
| `jti` | ✓ | Unique ID, ≥ 128 bits of randomness (22–128 b64u characters) |
| `bdy` | ✓ | b64u(SHA-256(request body bytes)). For an empty body, the hash of zero bytes. |
| `ath` | if token | b64u(SHA-256(ASCII(token))). Present if and only if the request carries a token. |
| `nonce` | if required | The latest server nonce (§6.5). Required on bound sessions (§9, §13). |

### 6.2 Verification

The receiver, using the URL it is publicly reachable at (not an internal address behind
a proxy), **MUST**:

1. Parse the payload; require `typ == "bound-proof"`.
2. Import `jwk` (§3.2) and verify the signature.
3. Require `|now − iat| ≤ 60`.
4. Require `htm` and `htu` to equal the received method and URL.
5. Require `bdy` to equal the hash of the received body bytes.
6. If the request carries a token: require `ath` to match it. Otherwise require `ath` to
   be absent.
7. If this endpoint requires server nonces (§6.5): require `nonce` to be one it issued
   recently, else fail with `use_nonce`.
8. Require that `jti` has not been seen before. Remember it for at least 120 seconds. If
   the cache is full of live entries, refuse the request (`503`) rather than forget any.
9. Output `jkt(jwk)`. The caller **MUST** compare it with the expected key: the token
   holder, the session key, or the key that started a Flow B request.

### 6.3 Why the body is covered

DPoP (RFC 9449) leaves the body unsigned. An attacker who can modify requests in transit
(a compromised proxy, TLS-terminating middleware, a browser extension) could then change
a payment amount while keeping a valid proof. Hashing the body costs little and closes
that gap.

### 6.4 Replay caches across instances

Resource servers running several instances **SHOULD** share the `jti` cache (e.g. in a
key-value store with TTL). Alternatively they **MAY** use per-instance caches if requests
are routed so that a proof can only reach one instance within its 60-second window.
`htu` binding already prevents replay to a *different* server.

### 6.5 Server nonces

The `iat` check bounds when a proof can be *used*, not when it was *made*. Script that
briefly controls a page holding a key can sign proofs dated hours ahead, and spend them
later with a stolen cookie. Server nonces close this: the proof must carry a value the
server issued moments before, which nobody can know in advance.

- Servers that require nonces send the current one in a `Bound-Nonce` response header on
  every response. A proof without a valid nonce is refused with `401` `use_nonce` (also
  carrying `Bound-Nonce`). The client re-signs with that nonce and retries once.
- A nonce **MUST** be unpredictable and short-lived (the reference implementation uses
  `<window>.<HMAC(server secret, window)>` with 30-second windows, accepting the current
  and previous window, so it needs no server-side storage).
- Bound sessions (§9) and issuer sessions (§13) **MUST** require nonces. Resource servers
  **MAY**. Their tokens live ≤ 5 minutes, which already bounds pre-signed proofs.
- A server that requires nonces from cross-origin browser clients **MUST** list
  `Bound-Nonce` in `Access-Control-Expose-Headers`, or the client can never read it.
- Because the client resends the same request after `use_nonce`, a server **MUST** check
  the proof, nonce included, *before* it consumes any single-use input carried by that
  request (a passkey challenge, a sign-in nonce, a user code). Otherwise the retry finds
  the input already spent, and a user whose passkey prompt outlasted a nonce cannot sign
  in.

---

## 7. Presenting a token to a resource server

```http
GET /notes/ HTTP/1.1
Host: notes.example
Authorization: Bound bnd1~eyJ…~eyJ…
Bound-Proof: eyJ0eXAiOiJib3VuZC1wcm9vZiIs….q3P0x8vVt2o…   (64-byte r‖s signature, b64u)
```

The resource server **MUST**:

1. Verify the token (§5.4) with `A` = its own origin.
2. Verify the proof (§6.2) with the token, and require `proof.jkt == token.holder`.
3. Map the request to an action and require authorization (§5.5).
4. Use `sub` as the user identifier. It is pairwise for this RS (§16).

On failure it responds `401` (authentication problems), `403` (`insufficient_grant`) or
`503` (`issuer_unavailable`, `busy`), with:

```http
WWW-Authenticate: Bound error="expired", error_description="token expired"
```

and a JSON body `{ "error": "…", "error_description": "…" }`. The error codes are in §14.

Resource servers that serve browsers directly **MUST** allow the `Authorization`,
`Bound-Proof` and `Content-Type` request headers in CORS and **SHOULD** expose
`WWW-Authenticate`. No cookies are involved, so `Access-Control-Allow-Origin: *` is safe.

---

## 8. Flow A: browser-mediated sign-in

### 8.1 The native form (target state)

In a browser that implements Bound natively, the RP page calls:

```js
const { identity, access } = await navigator.credentials.get({
  bound: {
    issuer: "https://id.example",
    nonce,                                  // from the RP server
    key: agentKey,                          // CryptoKeyPair, non-extractable
    claims: ["name"],
    access: { aud: ["https://notes.example"],
              grants: [{ res: "https://notes.example/notes/", act: ["read", "write"] }] }
  }
});
```

The browser shows its own account chooser and consent UI (as FedCM does), sends the
request to the issuer with the **browser-attested** RP origin, and returns the tokens
only to that page. A native implementation can additionally bind the agent key to the
browser profile (as DBSC does) and refuse to expose it to other origins.

### 8.2 The polyfill form (normative for v1)

Until browsers implement §8.1, Flow A runs over a popup and `postMessage`. The browser
still authenticates both ends: `MessageEvent.origin` cannot be forged, and
`postMessage(msg, targetOrigin)` delivers only if the target window's current origin
matches.

```
 RP page (rp.example)                                      Mediator popup (id.example)
 ─────────────────────                                     ─────────────────────────────
 click → window.open(metadata.mediator)  ───────────────▶  loads
                                         ◀───────────────  {type:"bound:ready"}         to "*" (repeated every 250 ms)
 check e.origin == issuer, e.source == popup
 {type:"bound:request", nonce, jkt,      ───────────────▶  check e.source == opener
   claims?, access?}  to issuer origin                     rp := e.origin  ← browser-authenticated
                                                           passkey sign-in if needed
                                                           consent screen shows rp
                                                           issuer mints tokens (aud = rp)
                                         ◀───────────────  {type:"bound:response", identity, access?}
                                                           or {type:"bound:response", error}
                                                           to rp origin only; window.close()
```

**RP page requirements:**

- **MUST** open the popup synchronously in a user gesture, without `noopener`.
- **MUST** accept messages only where `e.origin` is the issuer's origin and `e.source` is
  the popup.
- **MUST** send `bound:request` with `targetOrigin` = issuer origin.
- **MUST** treat a closed popup as cancellation.

**Mediator (issuer) requirements:**

- **MUST** refuse to proceed if `window.opener` is null.
- **MUST** take the RP identity *only* from `MessageEvent.origin` of a message whose
  `source` is `window.opener`. It **MUST NOT** accept an RP origin from URL parameters or
  message contents.
- **MUST** reject opaque origins (`"null"`) and any origin that is not HTTPS. Plain HTTP
  is acceptable only on loopback hosts (`localhost`, `127.0.0.1`, `[::1]`) for
  development. The issuer **MUST** apply the same rule again when minting.
- **MUST** handle only the first `bound:request`, and **MUST** take from it only `nonce`,
  `jkt`, `claims` and `access`. Anything else in the message is ignored.
- **MUST** display the RP origin on the consent screen, and for each requested grant the
  resource server, the actions, and *how much* of it: everything at the origin, a path and
  everything under it, or a single path. It **MUST** say how long access can be renewed
  (the grant's renewal window) and that it can be revoked.
- **MUST** protect the approve control against clickjacking, including double-click
  hijacking: the opener chooses where and when the popup appears. The control **MUST**
  stay disabled until the popup has been visible and focused for a short delay
  (≥ 500 ms), and **MUST** be disabled again whenever the popup loses focus or is hidden.
- **SHOULD** let a signed-in user switch accounts from the consent screen.
- **MUST** deliver the response with `targetOrigin` = that RP origin. If the opener has
  navigated elsewhere, the browser drops the message.
- **MUST** be served with `frame-ancestors 'none'` (no clickjacking) and **MUST NOT** be
  served with `Cross-Origin-Opener-Policy: same-origin`, which would sever the opener.
- The `bound:ready` message contains nothing secret, so `"*"` is acceptable there.

**Request members (`bound:request`):**

| Member | Req. | Meaning |
|---|---|---|
| `nonce` | ✓ | 16–128 characters, minted by the RP server, single-use, ≤ 5 min lifetime. The RP **SHOULD** seal it (MAC + expiry) rather than store it, and record it as used only when an identity token carrying it is accepted (§15.7). |
| `jkt` | ✓ | Thumbprint of the agent key (43 b64u characters) |
| `claims` | – | Array of attributes to release: `"name"`, `"username"`. Anything else is an error. |
| `access` | – | `{ aud: [rs-origin], grants: [...] }`: request an access token as well |

The issuer **MUST** validate every member's type and reject a request with a malformed
member (`400`). It **MUST NOT** guess at intent, e.g. by treating a string `claims` as a
list. Action names are looked up as the RS's own declared actions, never through
inherited properties.

**Issuer processing:**

1. Authenticate the user (§13). Show the RP origin, released claims and requested
   access in human terms. Get explicit approval.
2. Validate `access`: `aud` **MUST** be a single resource server known to the issuer;
   each grant's `res` **MUST** be within that origin; each action **MUST** be one the RS
   declares.
3. Mint the **identity token**: `sub` = pairwise(user, rp), `aud = [rp]`,
   `cnf.jkt = jkt`, `grants = []`, `nonce`, `claims`. Lifetime ≤ 120 s.
4. If access was requested: record a grant (§12) and mint an **access token**:
   `sub` = pairwise(user, rs), `aud = [rs]`, `cnf.jkt = jkt`, `grants`, `gid`, `rex`.

The issuer does **not** need proof that the RP page holds `jkt`. A token bound to a key
the requester doesn't hold is useless to everyone, and the RP origin, the security-relevant
input, is attested by the browser.

### 8.3 RP server: establishing the session

The page sends the identity token to its own server:

```http
POST /bound/session HTTP/1.1
Origin: https://rp.example
Authorization: Bound <identity token>
Bound-Proof: <proof by agent key>
Content-Type: application/json

{ "access": "<access token delegated to the RP server's key>" }    ← optional
```

The RP server **MUST**:

1. Verify the token (§5.4) with `A` = the RP origin, and the proof (§6.2), and require
   `proof.jkt == token.holder`.
2. Require a single-block token with empty `grants` (an identity token).
3. Require `nonce` to be one it issued and has not consumed, then consume it.
4. If `access` is present: verify it with `A` = the RS origin. Require its **root**
   `cnf.jkt` to equal the identity token's holder, and its current holder to be the RP
   server's own key (§11).
5. Create a bound session (§9) keyed to `token.holder`.

**Login CSRF and session fixation are prevented structurally.** An attacker who obtains
a valid identity token for *their own* account cannot get the victim's browser to
establish a session with it, because the victim's page signs proofs with the victim's
agent key, and that key is not the token's holder.

---

## 9. Bound sessions

After sign-in, the RP **SHOULD** use a cookie (`HttpOnly; Secure; SameSite=Lax`) **and
MUST** require every request on the session to carry a `Bound-Proof` (without `ath`)
whose `jkt` equals the session's agent key and which carries a fresh server nonce (§6.5).

- A stolen cookie without the agent key is rejected.
- The session **MUST** have a server-side lifetime, independent of the cookie's: an
  absolute limit (the reference RP uses 8 hours) and an idle timeout (1 hour).
- Ending a session (logout) **MUST** require the same proof as any other request, so a
  stolen cookie cannot be used to log the victim out.
- The RP **SHOULD** cap sessions per user (the reference RP ends the oldest beyond 10),
  so one account cannot fill the session store.
- Cookie-authenticated state-changing endpoints **MUST** also check the `Origin` header.
- When the user signs out, the page **SHOULD** give its root access token back
  (§12.4) and **SHOULD** discard its agent key and make a new one, so the next account
  used in that browser is not linkable to this one by `jkt`.

**What XSS on the RP can do.** Script running in the RP origin can *use* the agent key
while it runs (the key is an oracle), but cannot copy it out. Without server nonces it
could sign proofs dated hours ahead and spend them later with a stolen cookie. With them,
nothing it signed stays usable for more than about a minute after it stops running.
It can also delegate the current root access token to its own key (§11), which stays
usable until that token expires, at most one access-token lifetime. So the attacker
loses access within minutes of the tab closing, not instantly.

Where the browser supports Device Bound Session Credentials, RPs **MAY** use DBSC
instead of per-request proofs. The security property is equivalent.

---

## 10. Flow B: back-channel authorization

For clients without a browser at hand: CLIs, TVs, IoT devices, AI agents.

### 10.1 Request

```http
POST /bound/request HTTP/1.1
Bound-Proof: <proof by client key, no ath>
Content-Type: application/json

{ "client_name": "Notes CLI",
  "aud": ["https://notes.example"],
  "grants": [{ "res": "https://notes.example/notes/", "act": ["read"] }] }
```

```json
{ "request_id": "…", "user_code": "WDKM-QBPT",
  "interact": "https://id.example/device.html", "expires_in": 600, "interval": 2 }
```

The issuer records `jkt(proof)` as the only key that may collect the result.

`client_name` is self-asserted, so the issuer **MUST** keep it from passing as something
it is not. It must be 1–64 printable characters, with no control, format or bidi-override
characters, and must not contain `://`, `/` or `\`, so it cannot look like a site address.
Pending requests and their codes are state any key can create, and keys cost nothing.
Issuers **MUST** expire them and **MUST** limit how many one network source can create
(the reference issuer allows a burst of 10, then one every 30 seconds, per address), so one
client cannot fill the store for everyone. A global cap remains only as a memory backstop.
Flow B endpoints accept proofs from any key, so their replay cache **MUST** be separate
from the one sessions and renewal use (§15.7).

### 10.2 Interaction

The client shows the `interact` URL and the `user_code`. The user opens the URL on any
device, authenticates (§13), **types** the code, reviews the request, and approves or
denies. User codes **SHOULD** use an alphabet without vowels (no accidental words) and
carry ≥ 34 bits of entropy (e.g. 8 characters from 20 consonants, as RFC 8628
recommends). Issuers **MUST** rate-limit failed code lookups per user session (the
reference issuer allows 5 per minute, then answers `429` `slow_down`). Codes expire with
the request and are single-use.

The consent screen **MUST** present `client_name` as a name the device chose, visibly
distinct from a browser-verified origin (§8.2), and **MUST** show what is requested in
the terms of §8.2.

Guessing a code is low-value: lookup requires a signed-in user, and approving someone
else's request would give *that* client access to the *guesser's* account.

Issuers **MUST NOT** accept the user code pre-filled from the URL. Requiring the user to
type it defeats the cheapest form of consent phishing (§15.3).

### 10.3 Collection

```http
POST /bound/token HTTP/1.1
Bound-Proof: <proof by the same client key>

{ "request_id": "…" }
```

| Status | Body | Meaning |
|---|---|---|
| 428 | `{ "error": "authorization_pending" }` | Keep polling at `interval` |
| 403 | `{ "error": "access_denied" }` | User denied, or revoked the grant before collection |
| 400 | `{ "error": "invalid_request" }` | Expired, unknown, already collected, or **wrong key** |
| 200 | `{ "access": "<token>" }` | Done. The result can be collected **once**. |

At collection the issuer **MUST** check the grant again: if the user revoked it after
approving, no token is minted.

The request ID is not a secret. Knowing it is useless without the client key.

---

## 11. Attenuation and delegation

The holder of a token **MAY** append a block (§5.3) to:

- **narrow** it: an earlier `exp`, a smaller `aud`, fewer `grants`;
- **delegate** it: set `cnf.jkt` to another key. After that only the new key can use,
  narrow, delegate or renew it, and **the previous holder can no longer use it**.

The two are usually combined: *"here is a 60-second, read-only token, bound to your key."*

**In Flow A**, the root access token is bound to the browser's agent key. The page
delegates a copy to the RP server's key so the server can call the API:

```js
const forServer = await attenuate(rootAccess, agentKey, { to: rpServerPublicJwk });
```

The RP server **MAY** further delegate narrowed copies to workers, queues or
sub-services without contacting the issuer. Every hop is visible in the token (`by` of
each block), which gives a verifiable audit trail.

Resource servers verify the whole chain (§5.4). They do not need to know which party
delegated to which.

*Design note:* the browser holds the root, so the RP server's access depends on the user
continuing to use the RP. Delegated tokens cannot be renewed at the issuer (§12). This
gives "online access" by default. An RP that needs offline access can run Flow B from its
server, so that the grant is bound to the server's own key and the user approves it
explicitly as such.

---

## 12. Renewal and revocation

### 12.1 Grants

When a user approves access, the issuer stores a **grant**:
`{ gid, user, client, kind, aud, grants, jkt, created, rex, revoked }`. There is at most
one live grant per (user, client, key). Approving the same access again for the same key
extends it. Approving *different* access replaces it (the old grant is revoked), so a
broader earlier grant cannot linger, still renewable, behind a narrower new one. Users
**MUST** be able to list and revoke their grants at the issuer. The list **MUST** show
whether the client's name was verified by the browser (`kind` = site) or self-asserted
(`kind` = device). Issuers **SHOULD** cap live grants per user (the reference issuer
refuses a new one beyond 100 with `409` `too_many_grants`) and **SHOULD** forget grants
once their renewal window has closed, so the store does not grow without bound. Renewal
or revocation with a forgotten grant's token gives `401` `renewal_window_closed`.

### 12.2 Renewal

Access tokens are short-lived (≤ 5 minutes). There are **no refresh tokens**. To get a
fresh token, the holder signs a renewal request:

```http
POST /bound/renew HTTP/1.1
Authorization: Bound <root access token, possibly expired>
Bound-Proof: <proof by the holder>
```

The issuer **MUST**:

1. Verify the token as of `min(now, root.exp − 1)`. This accepts **expired** tokens
   while still checking every signature and structural rule. Audience is not checked.
2. Verify the proof against the **real** clock and require `proof.jkt == token.holder`.
3. Require a **single-block** token (`400` `not_renewable` otherwise). Delegated tokens
   are not renewable; their holders ask their delegator.
4. Require an access token: non-empty `grants` and a `gid`. Identity tokens get `401`
   `invalid_token`.
5. Look up `gid`: require the grant to exist, be bound to the same `jkt`, not be revoked,
   and have `rex > now`.
6. Mint a new token with the grant's *current* permissions.

`200 { "access": "<token>" }`, or `401` with `grant_revoked`, `renewal_window_closed`
or `invalid_token`.

Compared with refresh tokens:

- A refresh token is a long-lived bearer secret. Stealing it gives months of access. A
  Bound token that is stolen is inert, and the renewal credential *is* the
  non-exportable key.
- There is no rotation protocol, no reuse detection, and no refresh-token storage to
  protect.

### 12.3 Revocation

Revocation takes effect at the next renewal, so within one access-token lifetime
(≤ 5 minutes). Deployments needing faster revocation **MAY** have resource servers
consult the issuer about `gid` status (an introspection-style endpoint is left to §18),
or push revocations. The default deliberately keeps resource servers stateless and
offline-capable.

### 12.4 Revocation by the holder

A client gives access back, for example when its user signs out, with the same request
shape as renewal:

```http
POST /bound/revoke HTTP/1.1
Authorization: Bound <root access token, possibly expired>
Bound-Proof: <proof by the holder>
```

The issuer applies renewal steps 1–4 (§12.2), looks up the grant by `gid` and `jkt`, and
marks it revoked: `200 { "ok": true }`. Revocation is idempotent: a grant that is already
revoked, or has ended, also gives `200`. Only the root holder can do this. A delegate
holds a multi-block token and gets `400` `not_renewable`.

---

## 13. User authentication at the issuer

Issuers **MUST** authenticate users with **passkeys** (WebAuthn Level 3) with user
verification required, and **SHOULD NOT** offer passwords. Issuers:

- **MUST** check `clientDataJSON.type`, `challenge` (single-use, ≤ 5 min), `origin`
  (exactly the issuer origin), and that `crossOrigin` is not `true`;
- **MUST** check `rpIdHash`, the UP flag and the UV flag in `authenticatorData`;
- **MUST** verify the assertion signature with the stored credential public key;
- **SHOULD** reject an assertion whose non-zero signature counter fails to increase;
- **MAY** skip attestation (`"none"`);
- at registration, **MUST** require the credential ID the client reports to equal the one
  in the attested credential data, and **MUST** refuse a credential ID or username that
  already belongs to an account, checked again at verification time, not only when the
  options are issued;
- **SHOULD** issue challenges without storing them (sealed with a MAC and an expiry) and
  record a challenge as used only after the whole ceremony has succeeded, session proof
  included (§6.5, §15.7);
- **MUST** limit account creation and sign-in attempts per network source, and **SHOULD**
  cap sessions per account (the reference issuer ends the oldest beyond 10);
- **SHOULD** let users register more than one passkey, remove passkeys (never the
  last), and delete their account, which revokes all of its grants.

The issuer's own session cookie **SHOULD** be device-bound (DBSC, or per-request proofs
with server nonces as in §9) for the same reasons as §9. The reference issuer binds it to
a non-extractable key kept by its own pages. Issuer endpoints authenticated by that
cookie **MUST** check `Origin`. Account display names are shown on consent screens and
released as claims, so they **MUST** be length-limited printable strings.

Issuers **MUST** persist their signing key, accounts and grants durably: writes atomic,
and a store that cannot be read **MUST** stop the issuer rather than be replaced with a
fresh one, which would silently discard every account and grant.

Account recovery is out of scope. It is where real systems are weakest, and issuers
should treat it as carefully as sign-in itself.

---

## 14. Errors

JSON body `{ "error": <code>, "error_description": <text> }`. Token and proof errors on
resource servers also appear in `WWW-Authenticate: Bound error="<code>"`.

| Code | Status | Meaning |
|---|---|---|
| `missing_token` | 401 | No `Authorization: Bound` header |
| `malformed` | 401 | Token cannot be parsed or blocks are not chained |
| `invalid_issuer` | 401 | Unknown issuer or key ID |
| `invalid_signature` | 401 | A block's signature is invalid, or a block was not signed by the holder |
| `invalid_token` | 401 | Token is structurally valid but unacceptable (e.g. issued in the future, or an identity token at the renewal endpoint) |
| `expired` | 401 | Token expired. Renew it. |
| `invalid_audience` | 401 | Verifier is not in some block's `aud` (as a request parameter, §8.2/§10: `400`) |
| `invalid_proof` | 401 | Proof missing, invalid, stale, for a different request, or by the wrong key |
| `use_nonce` | 401 | Proof lacks a fresh server nonce; retry with the one in `Bound-Nonce` (§6.5) |
| `replayed` | 401 | Proof `jti` seen before |
| `insufficient_grant` | 403 | Token is valid but does not allow this action on this URL |
| `not_renewable` | 400 | Renewal or revocation with a multi-block token |
| `grant_revoked` | 401 | The grant behind the token was revoked |
| `renewal_window_closed` | 401 | `rex` has passed. Re-authorize. |
| `authorization_pending` | 428 | Flow B: user has not decided yet |
| `slow_down` | 429 | Flow B: too many wrong user codes from this session |
| `access_denied` | 403 | User denied, or revoked before collection |
| `invalid_request`, `invalid_grants`, `invalid_audience`, `invalid_nonce` | 400 | Bad request parameters |
| `issuer_unavailable` | 503 | The verifier could not fetch the issuer's keys |
| `too_many_grants` | 409 | The user has reached the issuer's limit on live grants (§12.1) |
| `rate_limited` | 429 | Too many requests from this network source; see `Retry-After` |
| `busy` | 503 | A bounded store (replay cache, pending requests) is at its memory backstop |

The reference implementation also uses these demo-specific codes, outside the protocol:
`login_required`, `bad_origin`, `no_session`, `invalid_challenge`, `passkey_rejected`,
`unknown_credential`, `unknown_code`, `username_taken`, `credential_exists`,
`last_passkey`, `invalid_access`, `access_expired`, `no_access`.

---

## 15. Security considerations

### 15.1 Threat model

The attacker may: read or modify network traffic outside TLS endpoints; read logs,
caches, browser history and storage; run a malicious website; send the user links; run
script in an RP origin (XSS); and steal cookies. The attacker may **not**: extract
non-exportable keys from a secure key store, break ES256 or SHA-256, or compromise the
issuer.

### 15.2 Attacks against OAuth/OIDC, and their status in Bound

| Attack (OAuth/OIDC) | Status in Bound | Why |
|---|---|---|
| Stolen access token (logs, Referer, storage, XSS exfiltration) | **Eliminated** | Use requires a proof by the non-exportable holder key |
| Stolen refresh token | **Eliminated** | No refresh tokens; renewal requires the holder key |
| Authorization code interception / injection | **Eliminated** | No codes; tokens never travel through URLs |
| Redirect URI manipulation, open redirectors | **Eliminated** | No redirects; delivery by browser-checked origin |
| Mix-up attacks | **Eliminated** | Responses come from one issuer origin to one RP origin, authenticated by the browser |
| CSRF on callback / login CSRF | **Eliminated** | Identity token is bound to the victim's own agent key (§8.3) |
| ID token replay to another RP | **Eliminated** | `aud` = RP origin, and holder binding |
| `alg: none`, key/algorithm confusion | **Eliminated** | One algorithm, strict key import, no `alg` field |
| Scope escalation by the client | **Eliminated** | Attenuation is intersection-only; issuer validates root grants |
| Phishing the user's credential at a fake IdP | **Eliminated** | Passkeys are origin-bound |
| Request replay | **Mitigated** | `jti` cache + 60 s window + `htu`/`htm`/`bdy` binding |
| Request tampering in transit (TLS-terminating middleboxes) | **Mitigated** | Body, method, URL and token are all signed |
| XSS on the RP | **Reduced** | Attacker can use keys while the script runs but cannot exfiltrate them; server nonces stop pre-signed proofs, so access ends within minutes (§9) |
| Consent phishing (malicious but honest-looking client) | **Not solved** | Inherent to delegation. Consent shows the browser-verified origin, the scope and the duration. |
| Clickjacking the consent screen | **Mitigated** | Approve is armed only after the popup is visible and focused (§8.2) |
| Device-code phishing (Flow B) | **Reduced** | Typed codes, unverified-name labelling, consent warnings, short expiry (§15.3) |
| Compromised issuer | **Not solved** | Inherent to any federation |

### 15.3 Flow B consent phishing

An attacker can start a Flow B request with *their own* key and persuade a victim to
approve it ("enter this code to claim your prize"). The resulting token belongs to the
attacker. No protocol can fully prevent this, because the user really did approve it.
Mitigations: codes are typed, never pre-filled from links; the consent screen shows how
long ago the request was made and warns never to enter codes received from others; the
client's name is labelled as unverified; requests expire in 10 minutes. Issuers
**SHOULD** also show the requesting client's approximate location or network (the
reference issuer shows its network address), and **MAY** restrict Flow B to clients they
have registered.

### 15.4 Popup polyfill limitations

The §8.2 polyfill relies on `window.opener`. Pages that set
`Cross-Origin-Opener-Policy: same-origin` on the RP side, or popup blockers, break it;
both fail closed (no tokens are released). A malicious page that opens the mediator gets
tokens for *its own* origin only, which are useless at any other RP. The native form
(§8.1) removes these limitations.

### 15.5 Compromise of an RP server

An attacker who has *only* the RP server's API process (its key and delegated tokens)
can act within those tokens' grants until they expire (≤ 5 minutes after the last
browser delegation). They cannot renew delegated tokens or mint new ones.

But the RP server normally also serves the RP's pages. An attacker who controls those
controls script in the RP origin, which is the XSS case (§9) for every user who visits:
they can use each visitor's agent key as an oracle while the page is open, and read the
root tokens it stores, renewing and delegating access to themselves for as long as users
keep coming back. Root tokens in the browser do **not** protect users from a compromised
RP origin. They limit the damage of a compromised *back end* that does not serve script.
Deployments should serve RP pages from infrastructure separate from API back ends, use
strict CSP and Subresource Integrity, and users can revoke the grant to end access at the
next renewal.

### 15.6 Time

Bound depends on loosely synchronized clocks (±60 s). Resource servers with unreliable
clocks will reject valid tokens and proofs. A server-supplied `nonce` in proofs (§18)
can remove the dependency for proofs.

### 15.7 Implementation hazards

- **Verify before parsing.** The reference implementation decodes a block's JSON only
  to find the key, verifies the signature over the received bytes, and never re-serializes.
- **Use the public URL** for `htu`, not one reconstructed from internal proxy headers.
- **Fail closed** on unknown token versions, extra `.` separators, and non-integer times.
- **Compare jkt values exactly.** They are canonical by construction.
- **Never crash on input.** Cookie, header, URL and percent-decoding must not throw past
  the request handler; one malformed request must not stop a server.
- **Don't let anonymous clients fill shared state.** A global cap that refuses new
  entries when full turns a memory problem into a lockout: one client fills it and
  everyone is refused. Instead:
  - *Seal, don't store,* what the server hands out (challenges, sign-in nonces): MAC it
    with an expiry, and record it only when it is *used* successfully, after the check
    that costs the caller real work (a passkey signature, an issuer-signed token).
  - *Limit per source* what must be stored (pending Flow B requests, accounts,
    sign-in attempts, sessions per account), and keep any global cap as a memory
    backstop only.
  - *Partition* shared caches by how much the caller had to prove: anonymous proofs
    must not fill the replay cache that sessions and renewal depend on.
  - Rate limiters themselves must fail open when their own tables are full, or they
    become the lockout.
- **Check before you consume.** Verify everything a request carries (proof, nonce,
  signatures) before spending any single-use input in it, so a client's retry still works
  (§6.5).
- **Validate types, not just presence.** Check that strings are strings and arrays are
  arrays, and look up names in own properties only (`constructor` is not an action).

---

## 16. Privacy considerations

- **Pairwise subjects:** `sub` = truncated HMAC(issuer secret, user ID ‖ audience
  origin). The same user has unrelated identifiers at different RPs and resource servers,
  so they cannot be joined by `sub`. It is stable per audience.
- **Minimal claims:** identity tokens carry only the attributes the user approved for
  that RP.
- **Issuer visibility:** as with OIDC, the issuer learns which RPs a user signs in to.
  The native form (§8.1) lets the browser hide the RP from the issuer until the user
  consents (as FedCM does).
- **Key correlation:** agent keys are per RP origin (IndexedDB is origin-scoped), so
  `jkt` cannot link a user across RPs. Within one RP, a key kept across sign-outs would
  link every account used in that browser, so RP pages **SHOULD** replace the key at
  sign-out (§9).

---

## 17. Relationship to existing standards

| Bound element | Closest existing standard | Difference |
|---|---|---|
| Bound-Proof | DPoP (RFC 9449), HTTP Message Signatures (RFC 9421) | Mandatory; covers the body; no algorithm negotiation |
| Token chain | Biscuit, macaroons | Every block is signed by the current holder, so a stolen token cannot even be attenuated; grants are simple prefix/action sets instead of a Datalog policy language |
| Flow A | FedCM; OIDC code flow + PKCE | Browser-authenticated origins instead of redirects; tokens are key-bound |
| Flow B | Device Authorization Grant (RFC 8628); GNAP (RFC 9635) | Only the requesting key can collect the result; no bearer device codes |
| Bound sessions | DBSC | Equivalent; DBSC preferred where available |
| Renewal | Refresh tokens | No long-lived secret; possession of a key is the credential |
| Grants | Rich Authorization Requests (RFC 9396) | Same idea, fixed small schema |
| Issuer metadata | OIDC Discovery, RFC 8414 | One small document; one algorithm |

Bound is closest in spirit to **GNAP** (key-bound clients, no bearer artefacts) and to
**FAPI 2.0** (few options). It goes further in mandating browser mediation, capability
tokens and passkeys.

---

## 18. Open issues

1. **Formal analysis.** Model Flows A and B, attenuation and renewal in Tamarin or
   ProVerif before anyone relies on this.
2. **Server nonces everywhere.** They are mandatory for sessions (§6.5). Should resource
   servers require them too, removing clock dependence entirely, at the cost of a round
   trip?
3. **Introspection / revocation push** for deployments that need sub-minute revocation.
4. **Richer grant conditions** (amount limits, time windows) without becoming a policy
   language.
5. **Native browser API** standardization (§8.1), likely as a FedCM extension.
6. **Multiple issuers per RP** and issuer choice UI (FedCM's account chooser solves this
   natively).
7. **Client identity.** Flow B relies on a self-asserted `client_name`. Issuers may want
   registered clients with verified names.
8. **Key loss and migration** for long-lived CLI or agent keys.

---

## Appendix A: worked example

In the shape the reference implementation produces (signatures elided). A root access token for `notes.example`,
bound to the user's agent key, then narrowed to read-only for 120 seconds and delegated
to the RP server's key.

**Block 0 (signed by the issuer):**

```json
{
  "v": 1, "typ": "bound", "iss": "https://id.example", "kid": "k7Qd2mVbX4o",
  "jti": "8Gu8FEhusWIW_z0TGTP2yw", "iat": 1792546117, "exp": 1792546417,
  "sub": "Vb1q0-3nW4l8m7JxgA2zKQ",
  "aud": ["https://notes.example"],
  "cnf": { "jkt": "shHLUUoHG_f7st8TlUwNYZ1KUtmcOdWqb7DSa-0ogq0" },
  "grants": [{ "res": "https://notes.example/notes/", "act": ["read", "write"] }],
  "gid": "q3T9xLm2Vb8KcR1w", "rex": 1792574917
}
```

**Block 1 (signed by the agent key, whose thumbprint is the `cnf.jkt` above):**

```json
{
  "prev": "lxEKZY3rwJdnKXc31WCl7j_5K8TeXlfBMPG57aNFcrE",
  "iat": 1792546117,
  "by": { "kty": "EC", "crv": "P-256",
          "x": "rnoM6gMQW0xHbPKJYb9cjkJhVeh1C13X7qQJVZfrqRE",
          "y": "o9rc9P67nDqWvXhGtblkBHURpdVDCsmnIisWJS5vS2E" },
  "exp": 1792546237,
  "grants": [{ "res": "https://notes.example/notes/", "act": ["read"] }],
  "cnf": { "jkt": "8OpvzqvA6q45oeheUfEbG5Dyi9X1EM_pH1kWAC3touk" }
}
```

Serialized, the token is about 1.1 KB: `bnd1~eyJzdWIiOi…~eyJwcmV2Ijoi…`.

**A request by the RP server (the new holder):**

```json
{
  "typ": "bound-proof",
  "jwk": { "kty": "EC", "crv": "P-256",
           "x": "-ph1k3r8RZm4F7ZsaIYs2KoWCff8WDEU3ndao7aHz_I",
           "y": "Jd29rYPxi0UN_Z_KHhpsMMirpvOLQ6ZVuhg3eFYlcn0" },
  "htm": "GET",
  "htu": "https://notes.example/notes/",
  "iat": 1792546117,
  "jti": "da6ddkBNU8DLfyp_F03g_g",
  "bdy": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
  "ath": "WElE1cECSbwoOnrImYyFDsoP5aYcTvrCAsZSfDGtBnA"
}
```

**What the resource server concludes:**

- Signatures: block 0 by issuer key `k7Qd2mVbX4o` ✓; block 1 by `shHL…` = root holder ✓;
  proof by `8Opv…` = current holder ✓.
- `exp` = min(1792546417, 1792546237). Audience includes `https://notes.example` ✓.
- Grant sets: `[{notes/: read, write}]` ∩ `[{notes/: read}]`. `GET /notes/` → `read` ✓;
  `POST /notes/` → `write` ✗ (403 `insufficient_grant`).
- If the user's browser presented this token itself, it would get `401 invalid_proof`:
  the browser delegated the token away.
