import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import * as Exit from "effect/Exit"
import * as Cause from "effect/Cause"
import * as Layer from "effect/Layer"
import * as Redacted from "effect/Redacted"

const randomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size)
  for (let i = 0; i < size; i += 65_536) globalThis.crypto.getRandomValues(bytes.subarray(i, i + 65_536))
  return bytes
}

/** A Web Crypto-backed `Crypto` service, equivalent to the platform layers. */
export const WebCrypto: Crypto.Crypto = Crypto.make({
  randomBytes,
  digest: (algorithm, data) =>
    Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, new Uint8Array(data))).pipe(
      Effect.map((buffer) => new Uint8Array(buffer))
    ),
  keys: Crypto.makeKeyOperations(globalThis.crypto.subtle)
})

export const CryptoLive = Layer.succeed(Crypto.Crypto, WebCrypto)

/**
 * The effect/jose services, built once with Web Crypto so the promise-based
 * tests can call them directly.
 */
export const { keys, signatures, encryption, tokens, keySets } = Effect.runSync(
  Effect.all({
    keys: JsonWebKey.make,
    signatures: JsonWebSignature.make,
    encryption: JsonWebEncryption.make,
    tokens: JsonWebToken.make,
    keySets: JsonWebKeySet.make
  }).pipe(Effect.provideService(Crypto.Crypto, WebCrypto))
)

/** Runs an effect, returning its value or throwing its failure. */
export const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> =>
  Effect.runPromiseExit(effect).then((exit) => {
    if (Exit.isSuccess(exit)) return exit.value
    throw Cause.squash(exit.cause)
  })

/** Runs an effect producing a `Redacted` token and returns the token text, for handing to jose. */
export const runToken = <E>(effect: Effect.Effect<Redacted.Redacted<string>, E>): Promise<string> =>
  run(effect).then(Redacted.value)

import {
  JsonWebAlgorithm,
  JsonWebEncryption,
  JsonWebKey,
  JsonWebKeySet,
  JsonWebSignature,
  JsonWebToken
} from "effect/jose"

/**
 * Every supported signature algorithm. Passing this as `algorithms` matches
 * jose's behaviour when no allow list is given, for like-for-like parity
 * comparisons. Real code should list only the algorithms it expects.
 */
export const anySignatureAlgorithm: ReadonlyArray<JsonWebAlgorithm.SignatureAlgorithm> =
  JsonWebAlgorithm.signatureAlgorithms
