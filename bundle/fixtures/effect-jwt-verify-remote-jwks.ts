import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"

const crypto = Crypto.make({
  randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
  digest: (algorithm, data) =>
    Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, new Uint8Array(data))).pipe(
      Effect.map((buffer) => new Uint8Array(buffer))
    ),
  keys: Crypto.makeKeyOperations(globalThis.crypto.subtle)
})
declare const token: string
const secret = new Uint8Array(32)

import * as FetchHttpClient from "effect/http/FetchHttpClient"
import * as JsonWebKeySet from "effect/jose/JsonWebKeySet"
import * as JsonWebToken from "effect/jose/JsonWebToken"

const program = Effect.gen(function*() {
  const keySets = yield* JsonWebKeySet.JsonWebKeySet
  const jwt = yield* JsonWebToken.JsonWebToken
  const keySet = yield* keySets.makeRemote("https://issuer.example/.well-known/jwks.json")
  return yield* jwt.verify(token, keySet, { algorithms: ["RS256", "ES256"], issuer: "https://issuer.example" })
})
Effect.runPromise(program.pipe(
  Effect.provideServiceEffect(JsonWebKeySet.JsonWebKeySet, JsonWebKeySet.make),
  Effect.provideServiceEffect(JsonWebToken.JsonWebToken, JsonWebToken.make),
  Effect.provide(FetchHttpClient.layer),
  Effect.provideService(Crypto.Crypto, crypto)
))
