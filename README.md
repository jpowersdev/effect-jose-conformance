# effect-jose-conformance

Conformance tests for the `effect/jose` modules (JWS, JWE, JWK, JWKS, JWT) and
the key operations added to Effect's `Crypto` service, developed on the `jose`
branch of a fork of [Effect](https://github.com/Effect-TS/effect).

The fork is pinned as a git submodule at `vendor/effect`, and its `effect`
package is linked directly from source, so no build step is needed.

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
| `test/errors.test.ts` | Each failure kind is a distinct tagged error, handled individually with `Effect.catchTag`. |
| `test/divergences.test.ts` | Each intentional difference from jose, pinned so it stays deliberate (see below). |

## Intentional differences from jose

- **Stricter:** duplicate `crit` values are rejected on verification, and so is non-canonical base64url (padding or whitespace).
- **Typed errors:** a key whose curve doesn't match the algorithm fails with `InvalidKeyError` and malformed PEM with `MalformedKeyError`; jose leaks raw Web Crypto exceptions in these cases. A key of the wrong type for the algorithm (e.g. RSA for ES256) is `InvalidKeyError`, where jose reports "not supported".
- **Unsupported on purpose:** JWE compression (`zip: "DEF"`, discouraged by RFC 8725), unsecured `alg: none` JWTs, RSA1_5, ES256K and ML-DSA.
- **Conventions:** durations are Effect `Duration` inputs (a bare number means milliseconds); unencoded flattened payloads are kept attached rather than detached.

Every effect/jose failure kind is its own tagged error class, defined in the module it relates to (for example `JsonWebSignature.SignatureVerificationError` or `JsonWebToken.TokenExpiredError`). To compare outcomes with jose, `src/outcome.ts` maps each tag to jose's equivalent `ERR_*` code; `InvalidKeyError` corresponds to the `TypeError` jose throws for key misuse. `test/errors.test.ts` checks that every tag is unique and mapped.

## Usage

```sh
git submodule update --init
pnpm install
pnpm test        # vitest
pnpm check       # tsc (TypeScript 7, matching the fork)
pnpm fork:update # move the pin to the latest commit on the fork's jose branch
```

The submodule currently points at a local checkout. Once the fork's `jose`
branch is pushed, switch it with
`git submodule set-url vendor/effect git@github.com:jpowersdev/effect.git`.
