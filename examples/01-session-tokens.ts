/**
 * # Session tokens
 *
 * Issue and verify short-lived session tokens signed with a shared secret
 * (HS256), with typed claims.
 *
 * - The secret comes from configuration as a `Redacted` value, so it never
 *   appears in logs.
 * - The claims schema types the payload on both sides, and encodes or decodes
 *   values such as dates.
 * - Issued tokens are `Redacted<JsonWebToken.Signed>`: unwrap them only where
 *   you send them, for example into a cookie.
 */
import * as Config from "effect/Config"
import * as ConfigProvider from "effect/ConfigProvider"
import * as Effect from "effect/Effect"
import * as Redacted from "effect/Redacted"
import * as Schema from "effect/Schema"
import { JsonWebToken } from "effect/jose"
import { CryptoLive } from "./CryptoLive.ts"

// The claims carried by a session token.
export const SessionClaims = Schema.Struct({
  ...JsonWebToken.RegisteredClaims.fields,
  sub: Schema.String,
  role: Schema.Literals(["admin", "member"])
})
export type SessionClaims = typeof SessionClaims.Type

const secret = Config.Redacted("SESSION_SECRET").pipe(
  // HS256 needs at least 32 bytes of key material.
  Effect.map((value) => Redacted.make(new TextEncoder().encode(Redacted.value(value))))
)

export const issueSession = (userId: string, role: SessionClaims["role"]) =>
  Effect.flatMap(secret, (key) =>
    JsonWebToken.sign({ sub: userId, role }, {
      key,
      schema: SessionClaims,
      protectedHeader: { alg: "HS256", typ: "JWT" },
      issuer: "urn:example:app",
      issuedAt: true,
      expirationTime: "15 minutes"
    }))

export const readSession = (token: string | Redacted.Redacted<string>) =>
  Effect.flatMap(secret, (key) =>
    JsonWebToken.verify(token, key, {
      schema: SessionClaims,
      algorithms: ["HS256"],
      issuer: "urn:example:app"
    })).pipe(Effect.map(({ payload }) => payload))

export const main = Effect.gen(function*() {
  const token = yield* issueSession("user-123", "admin")
  console.log("issued:", String(token)) // prints <redacted>
  const session = yield* readSession(token)
  console.log("session:", session.sub, session.role)

  // A tampered token fails with a typed error.
  const tampered = Redacted.value(token).slice(0, -2) + "xx"
  const error = yield* Effect.flip(readSession(tampered))
  console.log("tampered:", error._tag)
  return { session, error: error._tag }
}).pipe(
  Effect.provide(CryptoLive),
  Effect.provide(ConfigProvider.layer(
    ConfigProvider.fromUnknown({ SESSION_SECRET: "a-session-secret-of-at-least-32-bytes!" })
  ))
)

if (import.meta.main) Effect.runPromise(main)
