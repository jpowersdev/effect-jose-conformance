# Bundle size: effect/jose compared with jose

Measured with Effect's own bundle tooling (`packages/tools/bundle`: Rollup,
esbuild, terser, then gzip), against the built `jose` branch of the fork at
commit `9c62ca95a1`, and `jose` 6.2.12. Every size is minified and gzipped.
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
| Verify a JWT (HS256) | +8.3 KB | 5.6 KB |
| Verify against a remote key set (app already uses `HttpClient`) | +10.2 KB | 7.2 KB |

So in a typical Effect application, `effect/jose` costs about 1.4–1.5× what
`jose` does, for typed errors, `Schema`-typed claims, `Clock`-based time
checks, and the hardening described in the proposal.

## Without `Schema` in the application

For an application that uses Effect but not `Schema`, `effect/jose` also
brings in `Schema`, so the difference is larger.

| Fixture | effect/jose total | Added over an Effect + `Crypto` baseline (12.6 KB) | jose |
| --- | --- | --- | --- |
| Verify a JWT (HS256) | 32.5 KB | +19.8 KB | 5.6 KB |
| Sign a JWT | 30.9 KB | +18.3 KB | 5.1 KB |
| JWE round trip (`dir` + `A256GCM`) | 34.3 KB | +21.6 KB | 9.0 KB |
| Verify against a remote key set | 45.4 KB | +32.8 KB | 7.2 KB |
| Every module | 41.7 KB | +29.0 KB | 18.5 KB |

The remote key set row also includes `HttpClient`, `Stream`, and `Semaphore`,
which an application making HTTP requests already has.

## Where the cost comes from, and what could reduce it

- **`Schema`:** about 11.5 KB of the JWT verification cost when the application
  does not already use it (19.8 KB without `Schema` in the application, 8.3 KB
  with it). Defining errors with `Data.TaggedError` instead of
  `Schema.TaggedError` would remove that dependency, at the cost of errors
  that cannot be serialized (for example over RPC).
- **`effect/jose` itself:** the remainder, about 1.5× `jose` for the same
  features (8.3 KB against 5.6 KB for JWT verification). It has not been
  optimized for size yet.
