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

const program = JsonWebEncryption.JsonWebEncryption.use((jwe) => Effect.flatMap(jwe.encryptCompact("x", { key: secret, protectedHeader: { alg: "dir", enc: "A256GCM" } }), (token) => jwe.decryptCompact(token, secret)))
Effect.runPromise(program.pipe(Effect.provideServiceEffect(JsonWebEncryption.JsonWebEncryption, JsonWebEncryption.make), Effect.provideService(Crypto.Crypto, crypto)))
