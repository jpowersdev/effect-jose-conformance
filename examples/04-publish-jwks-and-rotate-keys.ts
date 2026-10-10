/**
 * # Publishing a key set and rotating signing keys
 *
 * The issuer side of example 03. An issuer signs with a private key and
 * publishes the public keys at a `jwks_uri` so others can verify.
 *
 * Rotation without downtime:
 * 1. Generate a new key and add its public key to the published set.
 * 2. Start signing with the new key (its `kid` tells verifiers which to use).
 * 3. Keep the old public key published until tokens it signed have expired,
 *    then remove it.
 *
 * Key IDs here are RFC 7638 thumbprints, so they are derived from the key and
 * stable across restarts.
 */
import type * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import { JsonWebKey, JsonWebKeySet, JsonWebToken } from "effect/jose"
import { CryptoLive } from "./CryptoLive.ts"

const newSigningKey = Effect.gen(function*() {
  const pair = yield* JsonWebKey.generateKeyPair("ES256")
  const kid = yield* JsonWebKey.thumbprint(pair.publicKey)
  return { ...pair, kid }
}).pipe(Effect.provide(CryptoLive))

/** The document to serve at `/.well-known/jwks.json`. */
const publish = (keys: ReadonlyArray<{ readonly publicKey: Crypto.Key; readonly kid: string }>) =>
  Effect.forEach(keys, ({ kid, publicKey }) =>
    Effect.map(JsonWebKey.exportJwk(publicKey), (jwk) => ({ ...jwk, kid, use: "sig", alg: "ES256" }))).pipe(
    Effect.map((keys) => ({ keys }))
  )

const issue = (key: { readonly privateKey: Crypto.Key; readonly kid: string }, sub: string) =>
  JsonWebToken.sign({ sub }, {
    key: key.privateKey,
    protectedHeader: { alg: "ES256", kid: key.kid },
    issuer: "https://auth.example",
    expirationTime: "1 hour"
  })

export const main = Effect.gen(function*() {
  // Before rotation: one key.
  const old = yield* newSigningKey
  const tokenFromOldKey = yield* issue(old, "alice")

  // Rotation: publish both keys, sign new tokens with the new key.
  const next = yield* newSigningKey
  const published = yield* publish([next, old])
  const tokenFromNewKey = yield* issue(next, "bob")

  // Verifiers fetch the published set (here, used directly) and pick keys by `kid`.
  const keys = yield* JsonWebKeySet.makeLocal(published)
  const verify = (token: Parameters<typeof JsonWebToken.verify>[0]) =>
    Effect.map(
      JsonWebToken.verify(token, keys, { algorithms: ["ES256"], issuer: "https://auth.example" }),
      ({ payload }) => payload.sub
    )
  const both = yield* Effect.all([verify(tokenFromOldKey), verify(tokenFromNewKey)])
  console.log("published kids:", published.keys.map((key) => key.kid))
  console.log("verified during rotation:", both)

  // After old tokens expire, stop publishing the old key: its tokens are now rejected.
  const afterRotation = yield* JsonWebKeySet.makeLocal(yield* publish([next]))
  const rejected = yield* Effect.flip(
    JsonWebToken.verify(tokenFromOldKey, afterRotation, { algorithms: ["ES256"], issuer: "https://auth.example" })
  )
  console.log("old key retired:", rejected._tag)
  return { verified: both, retired: rejected._tag }
}).pipe(Effect.provide(CryptoLive))

if (import.meta.main) Effect.runPromise(main)
