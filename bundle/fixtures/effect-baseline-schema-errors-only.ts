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

// Only the error classes JWT verification can raise, without the JOSE logic.
import { AlgorithmNotAllowedError, UnsupportedAlgorithmError } from "effect/jose/JsonWebAlgorithm"
import { InvalidKeyError, MalformedKeyError, UnsupportedKeyError } from "effect/jose/JsonWebKey"
import { JwsTooLargeError, MalformedJwsError, SignatureVerificationError, UnsupportedJwsHeaderError } from "effect/jose/JsonWebSignature"
import { ClaimValidationError, MalformedJwtError, TokenExpiredError } from "effect/jose/JsonWebToken"
;(globalThis as any).errors = [AlgorithmNotAllowedError, UnsupportedAlgorithmError, InvalidKeyError, MalformedKeyError, UnsupportedKeyError, JwsTooLargeError, MalformedJwsError, SignatureVerificationError, UnsupportedJwsHeaderError, ClaimValidationError, MalformedJwtError, TokenExpiredError]
