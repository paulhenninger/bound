# OAuth 2.0 + OpenID Connect: an analysis

This is the analysis that motivated Bound. It asks whether OAuth 2.0 + OpenID Connect
(OIDC), the de facto standard for web authentication and authorization, can be
replaced by something simpler and more secure, and where the answer is "not really".

The short version:

- For most websites, a simpler and more secure option **already exists**: passkeys plus
  device-bound sessions.
- A better *federation and delegation* protocol is possible, but most of OAuth/OIDC's
  complexity comes from the problems it solves. The gains come from narrowing the problem
  and removing options, not from cleverer cryptography.

---

## 1. Three different problems

OAuth + OIDC is routinely used for three jobs that are not the same:

| Problem | Example | What is actually needed |
|---|---|---|
| **1. Sign in to my own site** | A user signs into your app | Authentication + a session |
| **2. Federated sign-in** | "Sign in with Google" | Another party vouches for who the user is |
| **3. Delegated authorization** | Your app reads the user's Google Calendar | Limited access granted to a third party |

OAuth 2.0 (RFC 6749) was built for **#3**. OIDC added **#2** on top of it by defining an
ID token and a userinfo endpoint. Many sites deploy the full machinery for **#1**
(redirects, authorization codes, ID tokens, JWKS discovery, a hosted identity provider),
where none of it is needed.

### For problem #1, use passkeys + bound sessions

- **Passkeys (WebAuthn)** need no redirect dance, no token parsing and no client secrets.
  They resist phishing by construction: the browser puts the real origin into the signed
  data, so a look-alike domain gets a useless signature. No OAuth flow can guarantee
  that, because OAuth's security ends where the user types credentials into a page.
- **Sessions**: `HttpOnly; Secure; SameSite=Lax` cookies, and where available
  [Device Bound Session Credentials](https://github.com/w3c/webappsec-dbsc) (DBSC). With
  DBSC a stolen cookie is useless without a private key that never leaves the device.

That covers most sites, and it is both simpler and more secure than running OIDC against
yourself.

---

## 2. Where OAuth/OIDC's weaknesses come from

The cryptography in OAuth/OIDC is fine. Real-world failures trace back to four
structural choices.

### 2.1 Bearer tokens

Access tokens, refresh tokens, authorization codes and (in practice) ID tokens are
**bearer** credentials: whoever holds the string can use it. That makes every place a
token is copied a liability:

- server and proxy logs, APM traces, crash reports
- browser history and `Referer` headers (front-channel flows)
- `localStorage` reachable by any XSS
- mobile deep links intercepted by a malicious app with the same URL scheme
- refresh tokens copied out of a compromised device and used elsewhere for months

Sender-constrained tokens fix this (DPoP, RFC 9449; mTLS-bound tokens, RFC 8705), but
they are optional add-ons and rarely deployed outside high-security profiles.

### 2.2 The browser carries secrets through redirects

In the authorization-code flow, the authorization code (and in the implicit flow, the
token itself) travels in a URL between parties that don't trust each other, through a
browser the user controls and that malware may control. This one design choice produced
a whole family of attacks:

| Attack | What goes wrong | The patch |
|---|---|---|
| **Authorization code interception** | Another app or page receives the redirect | PKCE (RFC 7636) |
| **Code injection** | An attacker swaps their own code into the victim's session | PKCE, `nonce` |
| **CSRF on the callback / login CSRF** | The victim is signed into the *attacker's* account | `state`, `nonce` |
| **Mix-up attacks** | A client using several IdPs sends a code to the wrong one | `iss` in the response (RFC 9207) |
| **Open redirectors** | Loose `redirect_uri` matching leaks codes to attacker URLs | Exact string matching |
| **Token leakage via Referer / history** | Fragments and query strings end up in logs and headers | Drop the implicit flow; response modes |
| **Request tampering** | Parameters modified in the front channel | PAR (RFC 9126), JAR (RFC 9101) |

Each fix is real, but **each is a separate, optional mechanism that an implementer has
to know about and get right.**

### 2.3 Too many options

OAuth 2.0 and OIDC are frameworks, not protocols. A deployment chooses among:

- grant types: authorization code, implicit, resource owner password, client
  credentials, device code, refresh, token exchange, JWT bearer, CIBA…
- client types (confidential/public) and client authentication methods
  (`client_secret_basic`, `client_secret_post`, `client_secret_jwt`,
  `private_key_jwt`, mTLS…)
- response types and response modes (`query`, `fragment`, `form_post`, JARM…)
- token formats (opaque, JWT, JWE) and signing algorithms (negotiated through JOSE `alg`)
- scopes, claims requests, `acr_values`, `prompt`, `max_age`, …

Most published breaches are **misconfigurations inside this option space**, not breaks
of the core design: accepting `alg: none` or HS256-signed tokens verified with a public
key, prefix matching on redirect URIs, missing `state`, trusting unverified `email`
claims, or accepting ID tokens issued to a different client (`aud` not checked).

### 2.4 Security added late, as options

PKCE, `state`, `nonce`, PAR, DPoP, `iss` in the response, sender-constrained tokens,
refresh-token rotation: almost all of these were added years after the original design
to fix attacks found in the field. **All of them remain optional** in the base
specifications. A conformant implementation can still be an insecure one.

---

## 3. What the industry is already doing about it

- **OAuth 2.0 Security Best Current Practice (RFC 9700)** collects the mitigations above
  into recommendations.
- **OAuth 2.1** (draft) folds those recommendations into the base spec: PKCE always,
  no implicit or password grants, exact redirect matching, sender-constrained or
  rotated refresh tokens.
- **FAPI 2.0** profiles OAuth strictly: PAR + PKCE + sender-constrained tokens, few
  options, and a security model that was formally analyzed. It is the closest thing to
  "OAuth done right" and is deployed in open-banking ecosystems.
- **GNAP (RFC 9635)** is a clean-slate redesign: key-bound clients by default, a single
  request/continue model, rich access requests. It is technically better in several
  places but has seen almost no adoption. That shows **ecosystem inertia, not design,
  is the binding constraint**.
- **Browser-side building blocks**: FedCM (browser-mediated federated sign-in), DBSC
  (device-bound session cookies) and passkeys move trust decisions into the browser,
  which can see the true origin of every party.

---

## 4. What a better design looks like

The design principles that follow from this analysis, and that Bound adopts:

1. **Nothing is a bearer token.** Every token is bound to a key, and every use is signed.
   A copied token is inert.
2. **No secrets in redirects.** The browser mediates federation and authenticates the
   origins at both ends; tokens are delivered to an origin, not to a URL.
3. **One flow per job, no options.** One algorithm (ES256), one token format, one proof
   format; no negotiation for an attacker to downgrade.
4. **Permissions can be narrowed and delegated offline, never widened.** Capability-style
   tokens (as in macaroons and Biscuit) instead of opaque scope strings.
5. **Short lifetimes, renewal by proof.** No long-lived refresh tokens; the holder
   re-proves possession to get a new token, and the issuer re-checks the grant each time.
6. **Structured permissions** (resource + actions), not free-form scope strings.
7. **Phishing resistance at the root**: users authenticate to the issuer with passkeys.

[SPEC.md](../SPEC.md) turns these into a protocol, and `src/` implements it.

---

## 5. Caveats

- **Rolling your own security protocol is how breaches happen.** Bound is a design
  exercise with a reference implementation and tests. Before anyone trusts it, it needs
  formal analysis (ProVerif or Tamarin, as FAPI 2.0 received) and years of public scrutiny.
- **Device-bound keys make recovery and multi-device use harder.** Passkey sync solves
  this for the user's credential, but losing a client or agent key means re-authorizing.
- **Adoption is harder than cryptography.** OAuth/OIDC's value is that every platform,
  library and identity provider already speaks it.

---

## 6. Practical recommendations today

| Situation | Recommendation |
|---|---|
| Signing users in to **your own** site | Passkeys + device-bound sessions. Don't stand up OIDC against yourself. |
| **"Sign in with X"** | OIDC with a strict profile: authorization code + PKCE, exact redirect matching, PAR, verify `iss`/`aud`/`nonce`. Adopt FedCM where available. |
| **APIs and delegated access** | OAuth 2.1 / FAPI 2.0 with DPoP or mTLS-bound tokens. Never plain bearer tokens for anything valuable. Rotate or bind refresh tokens. |
| **Non-browser clients** (CLI, TV, agent) | Device authorization grant with sender-constrained tokens, and consent screens that warn about codes sent by someone else. |

Most of the "better protocol" already exists as parts you can deploy today: FedCM, DBSC,
DPoP, HTTP Message Signatures (RFC 9421), Rich Authorization Requests (RFC 9396),
Biscuit. What's missing is a single standard that makes them mandatory and removes
everything else. That is the job Bound attempts.
