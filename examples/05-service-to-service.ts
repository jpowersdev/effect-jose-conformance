/**
 * # Service-to-service authentication
 *
 * A caller signs a short-lived token with its private key; the callee checks
 * it with the caller's public key. Keys are loaded from configuration as PEM.
 *
 * - The private key is read as `Redacted` and never logged.
 * - Imported keys are `Crypto.Key`s bound to one algorithm, so `verify` needs
 *   no `algorithms` list.
 * - Tokens are scoped to one audience and live for a minute, which limits the
 *   damage if one leaks.
 */
import * as Config from "effect/Config"
import * as ConfigProvider from "effect/ConfigProvider"
import * as Effect from "effect/Effect"
import * as Redacted from "effect/Redacted"
import { JsonWebKey, JsonWebToken } from "effect/jose"
import { CryptoLive } from "./CryptoLive.ts"

/** In the calling service: sign a token for one request to `audience`. */
export const tokenFor = (audience: string) =>
  Effect.gen(function*() {
    const pem = yield* Config.Redacted("SERVICE_PRIVATE_KEY")
    const key = yield* JsonWebKey.importPkcs8(pem, "EdDSA")
    return yield* JsonWebToken.sign({}, {
      key,
      protectedHeader: { alg: "EdDSA" },
      issuer: "orders-service",
      subject: "orders-service",
      audience,
      issuedAt: true,
      expirationTime: "60 seconds"
    })
  })

/** In the receiving service: accept tokens from the orders service only. */
export const authenticate = (token: string) =>
  Effect.gen(function*() {
    const pem = yield* Config.String("ORDERS_SERVICE_PUBLIC_KEY")
    const key = yield* JsonWebKey.importSpki(pem, "EdDSA")
    const { payload } = yield* JsonWebToken.verify(token, key, {
      issuer: "orders-service",
      audience: "billing-service",
      maxTokenAge: "2 minutes"
    })
    return payload.sub
  })

export const main = Effect.gen(function*() {
  // Demo setup: generate a key pair and expose it as configuration.
  const pair = yield* JsonWebKey.generateKeyPair("EdDSA", { extractable: true })
  const config = ConfigProvider.fromUnknown({
    SERVICE_PRIVATE_KEY: Redacted.value(yield* JsonWebKey.exportPkcs8(pair.privateKey)),
    ORDERS_SERVICE_PUBLIC_KEY: yield* JsonWebKey.exportSpki(pair.publicKey)
  })

  const caller = yield* Effect.gen(function*() {
    const token = yield* tokenFor("billing-service")
    // Sent as `Authorization: Bearer ...`; received as a plain string.
    return yield* authenticate(Redacted.value(token))
  }).pipe(Effect.provide(ConfigProvider.layer(config)))

  const wrongAudience = yield* Effect.gen(function*() {
    const token = yield* tokenFor("shipping-service")
    return yield* Effect.flip(authenticate(Redacted.value(token)))
  }).pipe(Effect.provide(ConfigProvider.layer(config)))

  console.log("authenticated caller:", caller)
  console.log("token for another service:", wrongAudience._tag)
  return { caller, wrongAudience: wrongAudience._tag }
}).pipe(Effect.provide(CryptoLive))

if (import.meta.main) Effect.runPromise(main)
