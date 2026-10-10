import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import * as Schema from "effect/Schema"

// A typical Effect app: Crypto plus Schema decoding and a Schema-based error.
class AppError extends Schema.TaggedError<AppError>("AppError")("AppError", { message: Schema.String }) {}
const User = Schema.Struct({ id: Schema.String, roles: Schema.Array(Schema.Literals(["admin", "user"])) })

const crypto = Crypto.make({
  randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
  digest: (algorithm, data) =>
    Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, new Uint8Array(data))).pipe(
      Effect.map((buffer) => new Uint8Array(buffer))
    ),
  keys: Crypto.makeKeyOperations(globalThis.crypto.subtle)
})

const program = Schema.decodeUnknownEffect(User)({ id: "1", roles: ["admin"] }).pipe(
  Effect.flatMap(() => Effect.fail(new AppError({ message: "x" })))
)
Effect.runPromise(Effect.provideService(program, Crypto.Crypto, crypto))

import * as FetchHttpClient from "effect/http/FetchHttpClient"
import * as HttpClient from "effect/http/HttpClient"
import * as JsonWebKeySet from "effect/jose/JsonWebKeySet"
import * as JsonWebToken from "effect/jose/JsonWebToken"
declare const token: string
// The app already makes HTTP requests.
Effect.runPromise(HttpClient.get("https://api.example").pipe(Effect.provide(FetchHttpClient.layer)))
const verify = Effect.gen(function*() {
  const keySets = yield* JsonWebKeySet.JsonWebKeySet
  const jwt = yield* JsonWebToken.JsonWebToken
  const keySet = yield* keySets.makeRemote("https://issuer.example/.well-known/jwks.json")
  return yield* jwt.verify(token, keySet, { algorithms: ["RS256", "ES256"], issuer: "https://issuer.example" })
})
Effect.runPromise(verify.pipe(
  Effect.provideServiceEffect(JsonWebKeySet.JsonWebKeySet, JsonWebKeySet.make),
  Effect.provideServiceEffect(JsonWebToken.JsonWebToken, JsonWebToken.make),
  Effect.provide(FetchHttpClient.layer),
  Effect.provideService(Crypto.Crypto, crypto)
))
