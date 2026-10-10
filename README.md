# effect-jose-conformance

Conformance tests for the `effect/jose` modules (JWS, JWE, JWK, JWKS, JWT) and
the key operations added to Effect's `Crypto` service, developed on the `jose`
branch of a fork of [Effect](https://github.com/Effect-TS/effect).

The fork is pinned as a git submodule at `vendor/effect`, and its `effect`
package is linked directly from source, so no build step is needed.

## Example

[`examples/http-api-bearer-auth.ts`](examples/http-api-bearer-auth.ts) protects
an `HttpApi` with access tokens from an identity provider: the
`Authorization` middleware verifies bearer tokens against the provider's
remote key set and provides the current user. It serves the API with
`NodeHttpServer` and calls it with the generated `HttpApiClient`; only the
identity provider is simulated. Run it with `node examples/http-api-bearer-auth.ts`
(or Deno or Bun). `test/examples.server.test.ts` runs it on every server
runtime and checks what it logs.

## Bundle size

See [docs/bundle-size.md](docs/bundle-size.md). In an application that
already uses `Schema`, verifying a JWT adds 8.3 KB gzipped, against 5.6 KB for
`jose`.

## What is tested

| File | What it proves |
| --- | --- |
| `test/jws.interop.test.ts` | Every JWS algorithm (HS, RS, PS, ES, EdDSA, Ed25519) interoperates with [jose](https://github.com/panva/jose) in both directions, in compact, flattened and general serialization, including unencoded payloads (RFC 7797). |
| `test/jwe.interop.test.ts` | All 18 key management algorithms × 6 content encryption algorithms interoperate with jose in both directions, plus flattened JSON with AAD, multi-recipient general JSON, and ECDH-ES over P-256/384/521 and X25519. |
| `test/jwt.parity.test.ts` | JWT claim validation gives the same result and error code as jose across 33 scenarios (exp, nbf, iat, maxTokenAge, iss, sub, aud, typ, required claims, clock tolerance), plus JWT issuance, Schema-typed claims, Effect `Clock` integration, and encrypted JWTs. |
| `test/negative.parity.test.ts` | Malformed, tampered and hostile inputs (alg none, algorithm confusion, crit handling, short RSA keys, PBES2 limits, wrong keys, epk with private parts) fail exactly where jose fails, with the same error code. |
| `test/keys.test.ts` | RFC 7638 thumbprints, PEM (SPKI/PKCS#8) import and export, key generation and JWK import validation match jose. |
| `test/jwks.test.ts` | Local key set selection matches jose; remote key sets fetch lazily, cache, honour the refetch cooldown, and fail with typed errors. |
| `test/rfc7520.test.ts` | The worked examples from RFC 7520, with exact byte-for-byte reproduction wherever the inputs are deterministic. |
| `test/resolvers.test.ts` | Embedded-key verification matches jose's `EmbeddedJWK`; several matching keys fail by default like jose, and the explicit `multipleMatches: "tryEach"` option gives the same result as looping over jose's candidates; `KeyValueStore` storage reuses a fetched key set across fresh resolvers like jose's `jwksCache`. |
| `test/errors.test.ts` | Each failure kind is a distinct tagged error, handled individually with `Effect.catchTag`. |
| `test/divergences.test.ts` | Each intentional difference from jose, pinned so it stays deliberate (see below). |

## Intentional differences from jose

- **Stricter:** duplicate `crit` values are rejected on verification, and so is padded or whitespace-containing base64url. An embedded `jwk` must be in the protected header. HMAC keys must be at least as long as the hash (RFC 7518 §3.2).
- **Stricter defaults:** verification requires an explicit `algorithms` list unless the key is a `Crypto.Key` (which is bound to one algorithm), and JWTs must have `exp` unless `requireExpiration: false`. Parity tests pass every supported algorithm and `requireExpiration: false` to compare like with like.
- **Hardened by default:** compact tokens are capped at 64 KiB (`maxTokenLength`). Remote key sets require HTTPS (unless `allowInsecureHttp` is set), refuse URLs with credentials or a fragment, refuse redirects, and cap responses at 128 KiB and 64 keys. jose does none of these.
- **Typed errors:** a key whose curve doesn't match the algorithm fails with `InvalidKeyError` and malformed PEM with `MalformedKeyError`; jose leaks raw Web Crypto exceptions in these cases. A key of the wrong type for the algorithm (e.g. RSA for ES256) is `InvalidKeyError`, where jose reports "not supported".
- **Unsupported on purpose:** JWE compression (`zip: "DEF"`, discouraged by RFC 8725), unsecured `alg: none` JWTs, RSA1_5, ES256K and ML-DSA.
- **Conventions:** durations are Effect `Duration` inputs (a bare number means milliseconds); unencoded flattened payloads are kept attached rather than detached.

Every effect/jose failure kind is its own tagged error class, defined in the module it relates to (for example `JsonWebSignature.SignatureVerificationError` or `JsonWebToken.TokenExpiredError`). To compare outcomes with jose, `src/outcome.ts` maps each tag to jose's equivalent `ERR_*` code; `InvalidKeyError` corresponds to the `TypeError` jose throws for key misuse. `test/errors.test.ts` checks that every tag is unique and mapped.

## Runtimes

The suite runs unchanged on every supported JavaScript runtime. A Nix flake
pins the runtimes and the Playwright browsers, so results are reproducible:

```sh
nix run .#test-all        # everything below, with a summary
nix run .#test-node22     # Node.js 22 (also test-node24, test-node26)
nix run .#test-deno       # Deno
nix run .#test-bun        # Bun
nix run .#test-browsers   # Chromium, Firefox, and WebKit via Playwright
nix develop               # shell with Node.js, pnpm, Deno, Bun, and browsers
```

Server runtimes run Vitest's `server` project with the runtime's own
executable, so test workers run in that runtime; `test/runtime.server.test.ts`
fails if they do not. The `browser` project runs the same tests in each
browser, and `test/runtime.browser.test.ts` checks the engine. Remote key set
tests use an HTTP server started in Vitest's global setup (`src/jwksServer.ts`),
reachable from browsers.

Runtime-specific behaviour is asserted rather than skipped. Chromium's Web
Crypto has no 192-bit AES, so there the `A192*` algorithms must fail, with
`UnsupportedAlgorithmError` from effect/jose; `src/capabilities.ts` probes for
this.

Apps install dependencies with pinned Node.js and pnpm on first use. Extra
arguments are passed to Vitest, e.g. `nix run .#test-deno -- test/jwt.parity.test.ts`.

The npm `playwright` version must match nixpkgs' `playwright-driver`, since
the browsers come from nixpkgs.

## Development

```sh
git submodule update --init
pnpm install
pnpm test        # all projects with the local Node.js
pnpm check       # tsc (TypeScript 7, matching the fork)
pnpm fork:update # move the pin to the latest commit on the fork's jose branch
```

The submodule tracks the `jose` branch of
[jpowersdev/effect](https://github.com/jpowersdev/effect/tree/jose).
