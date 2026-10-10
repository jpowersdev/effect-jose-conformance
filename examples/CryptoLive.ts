/**
 * The `Crypto` service the examples run with.
 *
 * In an application, provide the layer for your runtime instead:
 *
 * - Node.js: `NodeCrypto.layer` from `@effect/platform-node`
 * - Bun: `BunCrypto.layer` from `@effect/platform-bun`
 * - Deno: `DenoCrypto.layer` from `@effect/platform-deno`
 * - Browsers: `BrowserCrypto.layer` from `@effect/platform-browser`
 *
 * Each of those builds the same Web Crypto-backed service as below. Building
 * it from `effect` alone keeps these examples runnable on every runtime
 * without extra packages.
 */
import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import * as Layer from "effect/Layer"

export const CryptoLive: Layer.Layer<Crypto.Crypto> = Layer.succeed(
  Crypto.Crypto,
  Crypto.make({
    randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
    digest: (algorithm, data) =>
      Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, new Uint8Array(data))).pipe(
        Effect.map((buffer) => new Uint8Array(buffer))
      ),
    keys: Crypto.makeKeyOperations(globalThis.crypto.subtle)
  })
)
