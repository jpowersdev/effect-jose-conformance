# Proposal: `effect/jose` and key operations on `Crypto`

**Status:** draft for discussion with the Effect maintainers. Nothing has been
opened upstream yet.

- **Implementation:** [`jose` branch of jpowersdev/effect](https://github.com/jpowersdev/effect/tree/jose)
- **Conformance tests:** [jpowersdev/effect-jose-conformance](https://github.com/jpowersdev/effect-jose-conformance)
- **Example:** [HttpApi bearer auth against a remote key set](../examples/http-api-bearer-auth.ts)
- **Bundle size:** [bundle-size.md](bundle-size.md)

## Summary

Add dependency-free implementations of the JOSE specifications to `effect`,
under a new `effect/jose` subpath, built on new key-based operations in the
existing `Crypto` service:

- **JWS:** signing and verification (RFC 7515, RFC 7797)
- **JWE:** encryption and decryption (RFC 7516)
- **JWK and JWKS:** keys and key sets (RFC 7517, RFC 7638, RFC 9278)
- **JWA:** the algorithms (RFC 7518, RFC 8037, RFC 9864)
- **JWT:** tokens, validated per the JWT best practices (RFC 7519, RFC 8725)

This replaces the most common reason Effect users add `jose` as a dependency,
in line with v4's direction of fewer dependencies and more built-in
primitives.

## Motivation

- **Zero dependencies:** applications using `HttpApi` authentication, OAuth/OIDC,
  or service-to-service tokens almost always pull in `jose`. v4 has been removing
  dependencies (find-my-way, multipasta, uuid, pg, mime, the YAML and TOML
  parsers); JOSE is a natural next step.
- **Effect-native ergonomics:** typed errors you can `catchTag`, time checks
  through `Clock` (so `TestClock` drives expiry), claims decoded with `Schema`,
  key sets fetched through `HttpClient`, and caching through layers.
- **One implementation everywhere:** everything platform-specific goes through
  the `Crypto`, `HttpClient`, and `KeyValueStore` services, so the same code runs
  on every runtime and platforms can supply their own implementations.

## Part 1: key operations on `Crypto`

Today `Crypto` covers random values, UUIDs/ULIDs, and digests. JOSE needs key
handling, so this adds ten methods, mirroring Web Crypto's `SubtleCrypto`:

`importKey`, `exportKey`, `generateKey`, `sign`, `verify`, `encrypt`,
`decrypt`, `deriveBits`, `wrapKey`, `unwrapKey`

Design points:

- **Opaque keys:** keys are opaque `Crypto.Key` handles (type, algorithm,
  extractability, usages), never raw native `CryptoKey`s. A key is bound to
  the implementation that created it; using it elsewhere fails with
  `PlatformError`.
- **Effect-owned types:** the algorithm parameter types (`KeyAlgorithm`,
  `SignAlgorithm`, `CipherAlgorithm`, and so on) belong to Effect, so core does not
  depend on DOM or Node type libraries.
- **`Crypto.makeKeyOperations(subtle)`** adapts any Web Crypto `SubtleCrypto`
  (accepted structurally as `SubtleCryptoLike`). The Node, Bun, Deno, and browser
  layers each gain one line to use it; `TestCrypto` forwards to its underlying
  service.
- **Compatibility:** `Crypto.make` takes the key operations as an optional
  `keys` field, so existing custom `Crypto` implementations keep working; without
  it, key operations fail with `PlatformError`.
- **Platform-specific implementations:** a platform can implement key operations
  natively (for example on `node:crypto` `KeyObject`s) for performance or for
  algorithms Web Crypto lacks, with no change to `effect/jose`.

Size: about 670 added lines across `Crypto.ts`, one internal adapter, and the
platform layers.

## Part 2: `effect/jose`

| Module | Responsibility |
| --- | --- |
| `JsonWebAlgorithm` | Algorithm identifiers and schemas |
| `JsonWebKey` | JWK and PEM (SPKI/PKCS#8) import and export, key generation, RFC 7638 thumbprints, opt-in `KeyCache` |
| `JsonWebKeySet` | Key selection from local and remote key sets |
| `JsonWebSignature` | Compact, flattened, and general JWS; key resolvers, including `embeddedKey` |
| `JsonWebEncryption` | Compact, flattened, and general JWE, including several recipients |
| `JsonWebToken` | Signed and encrypted JWTs, claim validation, Schema-typed claims |

Size: about 5,500 lines of source.

### API style

Functions take options objects and return Effects requiring `Crypto`:

```ts
const token = yield* JsonWebToken.sign({ role: "admin" }, {
  key: privateKey,
  protectedHeader: { alg: "ES256" },
  issuer: "urn:example:issuer",
  expirationTime: "2 hours",
  issuedAt: true
})

const { payload } = yield* JsonWebToken.verify(token, keySet, {
  algorithms: ["ES256"],
  issuer: "urn:example:issuer",
  schema: Claims
})
```

- **Keys** may be a `Crypto.Key`, raw secret bytes, or a JWK. Verification and
  decryption also accept a key resolver, a function from headers to a key, which
  is how key sets plug in.
- **Times** come from `Clock`, and durations are Effect `Duration` inputs.
- **Typed claims:** passing a `schema` to `verify`/`decrypt` decodes the claims
  and types the result. Passing one to `sign`/`encrypt` encodes typed claims
  first.
- **Secrets stay `Redacted`:** produced tokens are returned as `Redacted` values
  with a branded type (for example `Redacted<JsonWebToken.Signed>`). Tokens,
  secrets, and private JWKs may be passed in as `Redacted`, so a bearer token from
  `HttpApiSecurity.bearer` can be verified directly. Private key export
  (`exportPrivateJwk`, `exportPkcs8`) returns `Redacted` values, and schema errors
  never echo the claims.
- **Branded strings:** every formatted string the library produces is branded:
  - tokens (`JsonWebSignature.Compact`, `JsonWebEncryption.Compact`,
    `JsonWebToken.Signed`, `JsonWebToken.Encrypted`)
  - thumbprints
  - PEM
  - base64url members (`Base64Url`)

  Each brand has a schema for decoding values at a boundary. `alg` and `enc`
  are typed as the supported algorithms only.

### Errors

Every failure kind is its own `Schema.TaggedError`, defined in the module it
relates to, for example:

- `JsonWebSignature.SignatureVerificationError`
- `JsonWebToken.TokenExpiredError`
- `JsonWebKey.InvalidKeyError`
- `JsonWebAlgorithm.AlgorithmNotAllowedError`

There is no umbrella error. Each operation's error type is a union (for example
`JsonWebToken.VerifyError`). Unexpected platform failures surface as the
existing `PlatformError`, and misuse that the types already rule out is a
defect.

### Key sets

- **`makeLocal` and `makeRemote`:** `makeRemote` fetches lazily, caches, and
  refetches on an unknown `kid` after a cooldown. Concurrent fetches are
  coalesced. Customizing the fetch (headers, retries, a different `fetch`) is done
  by providing a different `HttpClient`.
- **Several matching keys** fail with `MultipleMatchingKeysError` unless the
  caller explicitly chooses `multipleMatches: "tryEach"`.
- **Freshness:** a response's `Cache-Control: max-age` shortens freshness,
  capped by `cacheMaxAge`. The resolver has an explicit `refresh` Effect for
  warming the cache at startup or refreshing on a schedule.
- **Persistence across restarts:** `storage: "keyValueStore"` persists fetched
  sets in `KeyValueStore`, for example for serverless cold starts. Choosing it
  adds `KeyValueStore` to the requirements at the type level; the default,
  `"memory"`, does not.

### Key caching

`JsonWebKey.KeyCache` is a `Context.Reference` that does nothing by default.
Providing `JsonWebKey.layerKeyCache({ capacity, timeToLive })` in the root
layer caches imported JWKs, keyed by content, using `Cache`. It never adds a
requirement.

## Security posture

- **No `alg: none`:** the `none` algorithm is never accepted.
- **Explicit algorithms:** verification requires an `algorithms` list unless the
  key is a `Crypto.Key`, which is already bound to one algorithm (RFC 8725
  section 3.1). This is enforced in the types.
- **Expiry required:** JWTs must carry `exp`, on both issue and verification,
  unless `requireExpiration: false` opts out.
- **Algorithm pinning:** the token's `alg` must match the key's type, curve, and
  size. Algorithm-confusion attacks (for example an HMAC token "signed" with a
  public key) are tested.
- **RSA key size:** RSA keys must be 2048 bits or larger.
- **`crit` handling:** critical header extensions must be declared as understood.
- **PBES2 limits:** PBES2 must be explicitly allowed, and its iteration count is
  capped.
- **No decryption oracle:** a failed key unwrap falls back to a random content
  key, so failures don't reveal which step failed (RFC 7516 section 11.5).
- **Strict base64url:** padding and whitespace are rejected.
- **HMAC key length:** HMAC keys must be at least as long as the hash (RFC 7518
  section 3.2).
- **Size limits:** compact tokens are capped at 64 KiB by default, before any
  decoding.
- **Remote key sets** must use HTTPS unless `allowInsecureHttp` is set. URLs with
  credentials or a fragment are rejected, redirects are refused, and responses
  are capped (128 KiB and 64 keys by default). These ideas come from community
  work, notably `@yielded/jose`.

## Evidence

A separate conformance repository pins the fork and tests it against
[jose](https://github.com/panva/jose) and the RFCs:

- **Interoperability:** every JWS algorithm, and all 108 JWE key-management ×
  content-encryption pairs, round-trip with jose in both directions, in every
  serialization.
- **Matching behaviour:** under equivalent options, 33 JWT claim scenarios plus
  tampered, malformed, and hostile inputs give the same outcome and error as jose.
  Where the defaults differ on purpose, a dedicated test pins each difference.
- **RFC 7520 worked examples:** reproduced byte for byte wherever the inputs
  are deterministic.
- **Every runtime, through a Nix flake:** Node.js 22, 24, and 26, Deno, Bun,
  Chromium, Firefox, and WebKit. Runtime-specific behaviour (Chromium's lack of
  192-bit AES) is asserted rather than skipped.
- **Totals:** 533 tests on each server runtime and 1,599 in browsers, including a
  runnable end-to-end example. The fork
  adds 89 unit tests and 7 type tests of its own, plus tests for the `Crypto` key
  operations.

## Intentional differences from jose

- **Stricter defaults:** an explicit `algorithms` list, a required `exp`, a
  minimum HMAC key length, size limits, and the remote key set rules (see
  Security posture). jose does none of these.
- **Stricter parsing:**
  - duplicate `crit` values are rejected on verification
  - padded or whitespace-containing base64url is rejected
  - an embedded `jwk` must be in the protected header
- **Better typed:** a key of the wrong type or curve, malformed PEM, and
  algorithms the runtime cannot perform each get a specific error, where jose
  leaks raw runtime exceptions or reports "not supported".
- **Conventions:**
  - durations are `Duration` inputs (a bare number means milliseconds)
  - unencoded (`b64: false`) payloads stay attached in flattened JWS

## Not supported, deliberately

| Feature | Reason |
| --- | --- |
| JWE compression (`zip: "DEF"`) | Discouraged by RFC 8725 (length leaks, decompression bombs); little demand. Could be added later behind an explicit opt-in. |
| Unsecured JWTs (`alg: "none"`) | The best-known JWT vulnerability. |
| RSA1_5 | Padding-oracle attacks; not available in Web Crypto. |
| ES256K | secp256k1 is not in Web Crypto. Could be added later through platform `Crypto` layers. |
| ML-DSA | The JOSE specification is still a draft, and runtime support is patchy. |

Each fails with a specific error, and tests pin that behaviour.

## Open questions

1. **Growing `Crypto`:** is extending `Crypto` acceptable, or should key
   operations live in a separate service, or be exposed differently?
2. **`makeKeyOperations` and `SubtleCryptoLike`:** are the name and placement
   right? Is a structurally typed parameter with `any` acceptable?
3. **Placement:** `effect/jose` as a stable subpath of `effect`, or in an
   unstable location first?
4. **Delivery:** is the PR plan below the preferred split?
5. **Cross-runtime testing:** should the conformance suite (or part of it) live in
   the Effect repository, or stay external?
6. **Bundle size:** measured in [bundle-size.md](bundle-size.md). In an
   application that already uses `Schema`, verifying a JWT adds 8.3 KB
   (gzipped), against 5.6 KB for `jose`. Without `Schema` in the application it
   adds 19.8 KB, mostly `Schema` itself, because errors are
   `Schema.TaggedError`s. Is that trade-off acceptable, or should errors use
   `Data.TaggedError`?

## Suggested PR plan

1. **`Crypto` key operations:** the service methods, `makeKeyOperations`, the
   platform layers, `TestCrypto`, and tests. This is small, reviewable on its own,
   and useful beyond JOSE (webhook signatures, signed cookies).
2. **`effect/jose`:** the modules, tests, type tests, and documentation, with a
   link to the conformance results.
