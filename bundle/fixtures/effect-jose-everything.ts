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
const program = Effect.all([JsonWebToken.sign({}, { key: secret, protectedHeader: { alg: "HS256" }, expirationTime: "1 hour" }), JsonWebToken.verify(token, secret, { algorithms: ["HS256"] }), JsonWebToken.encrypt({}, { key: secret, protectedHeader: { alg: "dir", enc: "A256GCM" }, expirationTime: "1 hour" }), JsonWebToken.decrypt(token, secret), JsonWebSignature.verifyGeneral({ payload: "", signatures: [] }, secret, { algorithms: ["HS256"] }), JsonWebEncryption.decryptGeneral({ ciphertext: "", recipients: [] }, secret), JsonWebKey.importPkcs8("", "ES256"), JsonWebKey.thumbprint({ kty: "oct", k: "" }), JsonWebKeySet.makeLocal({ keys: [] })])
Effect.runPromise(Effect.provideService(program, Crypto.Crypto, crypto) as any)
