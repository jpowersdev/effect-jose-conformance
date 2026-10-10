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

import * as JsonWebEncryption from "effect/jose/JsonWebEncryption"
import * as JsonWebKey from "effect/jose/JsonWebKey"
import * as JsonWebKeySet from "effect/jose/JsonWebKeySet"
import * as JsonWebSignature from "effect/jose/JsonWebSignature"
import * as JsonWebToken from "effect/jose/JsonWebToken"

// Everything: one use of every module.
const program = Effect.gen(function*() {
  const jwt = yield* JsonWebToken.JsonWebToken
  const jws = yield* JsonWebSignature.JsonWebSignature
  const jwe = yield* JsonWebEncryption.JsonWebEncryption
  const keys = yield* JsonWebKey.JsonWebKey
  const keySets = yield* JsonWebKeySet.JsonWebKeySet
  return yield* Effect.all([jwt.sign({}, { key: secret, protectedHeader: { alg: "HS256" }, expirationTime: "1 hour" }), jwt.verify(token, secret, { algorithms: ["HS256"] }), jwt.encrypt({}, { key: secret, protectedHeader: { alg: "dir", enc: "A256GCM" }, expirationTime: "1 hour" }), jwt.decrypt(token, secret), jws.verifyGeneral({ payload: "", signatures: [] }, secret, { algorithms: ["HS256"] }), jwe.decryptGeneral({ ciphertext: "", recipients: [] }, secret), keys.importPkcs8("", "ES256"), keys.thumbprint({ kty: "oct", k: "" }), keySets.makeLocal({ keys: [] })])
})
Effect.runPromise(program.pipe(
  Effect.provideServiceEffect(JsonWebToken.JsonWebToken, JsonWebToken.make),
  Effect.provideServiceEffect(JsonWebSignature.JsonWebSignature, JsonWebSignature.make),
  Effect.provideServiceEffect(JsonWebEncryption.JsonWebEncryption, JsonWebEncryption.make),
  Effect.provideServiceEffect(JsonWebKey.JsonWebKey, JsonWebKey.make),
  Effect.provideServiceEffect(JsonWebKeySet.JsonWebKeySet, JsonWebKeySet.make),
  Effect.provideService(Crypto.Crypto, crypto)
) as any)
