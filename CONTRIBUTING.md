# Contributing to Bound

Thanks for looking. Bound is a design exercise: a protocol specification
([SPEC.md](SPEC.md)) and a reference implementation that shows it working. The most
valuable contributions are the ones that make the design sounder:

- **Attacks.** A way to use, widen, replay or steal something the spec says you can't.
  These matter most, even as a rough sketch.
- **Spec problems.** Ambiguities, contradictions, requirements the implementation can't
  meet, claims in §15 that are stronger than the design supports.
- **Implementation bugs**, especially where the code is weaker than the spec.
- **Usability** of the demo flows, including the consent screens and error messages.

New features are less useful than all of the above. If you want to add one, open an
issue first so we can agree it belongs in v1 rather than in §18 (open issues).

## Getting started

You need Node.js 22 or later. There is nothing to install.

```bash
npm test     # 79 tests, about a second
npm start    # the demo: issuer :4100, Notebook :4200, Notes API :4300
```

See the [README](README.md) for a walk-through of the demo. Use `localhost`, not
`127.0.0.1`: origins and passkeys are bound to the exact address.

## Ground rules

1. **No dependencies.** Everything uses Node built-ins and WebCrypto. This keeps the
   code small enough to audit in one sitting. A change that needs a package needs a very
   good reason.
2. **`src/lib/` runs in browsers too.** Files the pages load (`agent.js`, `client.js`,
   `encoding.js`, `keys.js`, `origins.js`, `proof.js`, `token.js`) must not import
   `node:` modules or use `Buffer` or `process`. Server-only helpers (`http.js`,
   `state.js`, `verifier.js`, `webauthn.js`) may.
3. **The spec and the code change together.** If you change behavior a verifier,
   issuer or client relies on, update SPEC.md in the same pull request. That includes
   the error table (§14), the attack table (§15.2) and the appendix if they're affected.
   Use BCP 14 keywords (**MUST**, **SHOULD**, **MAY**) deliberately.
4. **Every security fix comes with a regression test** that fails without the fix.
5. **Keep it boring.** One algorithm, one token format, one proof format. Options and
   negotiation are what Bound exists to avoid.

## Code style

Match the surrounding code: ES modules, two-space indentation, single quotes,
semicolons, small functions. Comments explain *why*, not what, and are as sparse as the
code around them. There is no linter or formatter, so please read your diff once as a
reviewer would.

## Tests

Tests use Node's built-in runner (`node:test`) and live in `test/`:

| File | What it covers |
|---|---|
| `token.test.js`, `proof.test.js`, `webauthn.test.js` | Library units: tokens, proofs, passkeys |
| `hardening.test.js` | Library-level regressions from the security review |
| `browser-side.test.js` | Mediator popup and RP page `postMessage` handling, consent-button guard (fake windows) |
| `e2e.test.js` | All three servers over real HTTP: both flows, delegation, renewal, attacks |
| `e2e-hardening.test.js` | End-to-end regressions from the security review |

Helpers:

- `helpers/soft-authenticator.js`: a software passkey. `create()` and `get()` return what
  a browser would send. Options let you forge flags, challenges and credential IDs.
- `helpers/browser.js`: a simulated browser with a cookie jar and `Origin` headers. Pass
  `boundOrigins: [ISSUER]` and it signs a proof on every issuer call, as the real issuer
  pages do.

End-to-end tests start real servers on fixed ports: 5100–5300 (`e2e.test.js`) and
5600–5619 (`e2e-hardening.test.js`). Pick an unused range for a new file. Tests write
issuer state to a temporary directory, never to `data/`.

Write attack tests the way the attacker would: forge the request by hand rather than
calling a helper that would refuse to build it. Assert the exact status and error code.

## Pull requests

- Branch from `main` and open a pull request against it.
- CI runs the tests on Ubuntu and Windows with Node 22 and 24. It must pass.
- In the description, say what changes for the threat model, if anything: which attack
  this stops or enables, and which spec section it touches.
- Keep pull requests to one concern. A spec clarification and a refactor are two PRs.

## Reporting security problems

Bound is not meant to be deployed (see the status line in SPEC.md), so weaknesses in
the protocol or the reference implementation can be discussed in public issues. That
is how the design gets better.

If you know of a deployment that uses Bound, or would rather not post publicly, contact
the maintainer privately through their GitHub profile first.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE), like the rest of the project.
