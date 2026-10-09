import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import * as Exit from "effect/Exit"
import * as Cause from "effect/Cause"
import * as Layer from "effect/Layer"

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

/** Runs an effect that needs `Crypto`, returning its value or throwing its failure. */
export const run = <A, E>(effect: Effect.Effect<A, E, Crypto.Crypto>): Promise<A> =>
  Effect.runPromiseExit(Effect.provide(effect, CryptoLive)).then((exit) => {
    if (Exit.isSuccess(exit)) return exit.value
    throw Cause.squash(exit.cause)
  })
