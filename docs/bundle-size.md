# Bundle size: effect/jose compared with jose

Measured with Effect's own bundle tooling (`packages/tools/bundle`: Rollup,
esbuild, terser, then gzip), against the built `jose` branch of the fork at
commit `310fed1ec2`, and `jose` 6.2.12. Every size is minified and gzipped.
The fixtures are in [`bundle/fixtures`](../bundle/fixtures), and
[`bundle/measure.sh`](../bundle/measure.sh) reproduces the numbers.

## What an Effect application pays

For an Effect application, the relevant number is what `effect/jose` *adds*,
because the application already includes Effect. Most Effect applications
also use `Schema` (any `HttpApi` application does), and `effect/jose` uses
`Schema` for its error classes, brands, and claims decoding, so that cost is
usually already paid.

| Added to an app that already uses `Schema` | effect/jose | jose |
| --- | --- | --- |
| Verify a JWT (HS256) | +14.7 KB | 5.6 KB |
| Verify against a remote key set (app already uses `HttpClient`) | +17.1 KB | 7.2 KB |
| Verify a JWS with the `JsonWebSignature` service alone | +8.9 KB | 5.6 KB (JWT) |

So in a typical Effect application, `effect/jose` costs about 2.4–2.6× what
`jose` does, for typed errors, `Schema`-typed claims, `Clock`-based time
checks, and the hardening described in the proposal. About 6 KB of that is
the price of exposing the operations as services (see below).

## Without `Schema` in the application

For an application that uses Effect but not `Schema`, `effect/jose` also
brings in `Schema`, so the difference is larger.

| Fixture | effect/jose total | Added over an Effect + `Crypto` baseline (12.6 KB) | jose |
| --- | --- | --- | --- |
| Verify a JWT (HS256) | 38.8 KB | +26.2 KB | 5.6 KB |
| Sign a JWT | 38.9 KB | +26.2 KB | 5.1 KB |
| JWE round trip (`dir` + `A256GCM`) | 35.3 KB | +22.7 KB | 9.0 KB |
| Verify against a remote key set | 52.9 KB | +40.3 KB | 7.2 KB |
| Every module | 47.4 KB | +34.7 KB | 18.5 KB |

The remote key set row also includes `HttpClient`, `Stream`, and `Semaphore`,
which an application making HTTP requests already has.

## Services and tree-shaking

The operations are methods of services (`JsonWebToken`, `JsonWebSignature`,
and so on), so that `Crypto` is a requirement of their layers rather than of
every call. A service object holds all of its methods, so a bundler keeps
every method of every service the application uses, even ones it never calls.

The largest effect is on JWT verification: the `JsonWebToken` service also
signs, encrypts, and decrypts, so verifying a signed JWT bundles the JWE
implementation too. Measured in an application that already uses `Schema`:

| Verifying | Added |
| --- | --- |
| A JWS, through the `JsonWebSignature` service (signing included) | +8.9 KB |
| A JWT, through the `JsonWebToken` service (signing and JWE included) | +14.7 KB |
| A JWT, with the earlier function-based API (commit `9c62ca95a1`) | +8.3 KB |

Moving encrypted JWTs into a service of their own would recover most of the
difference: verifying a signed JWT would then cost a little more than the
`JsonWebSignature` figure.

## Where the cost comes from

Breaking down JWT verification in an application that already uses `Schema`
(+14.7 KB, against 5.6 KB for `jose`):

1. **Unused service methods: about 6 KB.** JWT signing, encryption, and
   decryption, as described above.
2. **The JOSE logic is the same size as jose.** By module, `effect/jose`'s own
   code renders to about 27 KB unminified, against about 26 KB for the
   equivalent `jose` modules.
3. **Error classes: about 2.4 KB.** Verification can raise twelve error types,
   each a `Schema.TaggedError` with `Schema`-typed fields. Defining them builds
   `Schema` structures at load time, which pulls in more of `SchemaAST`,
   `SchemaIssue`, and `Formatter` than the baseline application uses. The
   fixture `effect-baseline-schema-errors-only.ts` references only those twelve
   classes and adds 2.4 KB on its own. (The brand schemas are tree-shaken out of
   verification bundles.)
4. **Smaller contributors:**
   - The decoding path for the optional claims `schema` lives inside `verify`,
     so it is bundled even when no schema is passed.
   - `effect/encoding`'s Base64 module is used for base64url.
   - A few more Effect combinators.

Without `Schema` in the application, the `Schema` runtime itself adds about
11.5 KB more (26.2 KB against 14.7 KB).

## What could reduce it

- **A separate service for encrypted JWTs:** saves about 6 KB for applications
  that only use signed JWTs, the common case.
- **Errors as `Data.TaggedError`:** saves about 2.4 KB in an application that
  uses `Schema`, and about 14 KB in one that does not. Errors could then no
  longer be serialized, for example over RPC.
- **Separate schema-aware functions:** splitting `verify`/`sign` from their
  schema-aware forms would let bundlers drop the `Schema` decoding path when it
  is unused.
- **A smaller base64url decoder** inside `effect/jose` would save a little, at
  the cost of duplicating `effect/encoding`.
