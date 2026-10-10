/**
 * # Encrypted tokens and secret rotation
 *
 * Signed tokens are readable by anyone who holds them. When a token carries
 * data the holder should not see (an email address, internal IDs), encrypt it
 * instead (JWE). Here a server encrypts its own session state with a secret
 * key (`dir` + `A256GCM`).
 *
 * - Sensitive claims are decoded as `Redacted` with `Schema.RedactedFromValue`,
 *   so logging the decoded session does not reveal them.
 * - Rotating the secret without logging everyone out: decrypt with the current
 *   secret, and fall back to the previous one.
 */
import * as Effect from "effect/Effect"
import * as Redacted from "effect/Redacted"
import * as Schema from "effect/Schema"
import { JsonWebToken } from "effect/jose"
import { CryptoLive } from "./CryptoLive.ts"

const Session = Schema.Struct({
  ...JsonWebToken.RegisteredClaims.fields,
  sub: Schema.String,
  email: Schema.RedactedFromValue(Schema.String)
})

const encryptSession = (key: Uint8Array, session: { readonly sub: string; readonly email: Redacted.Redacted<string> }) =>
  JsonWebToken.encrypt(session, {
    key,
    schema: Session,
    protectedHeader: { alg: "dir", enc: "A256GCM" },
    expirationTime: "8 hours"
  })

/** Decrypts with the current secret, falling back to the previous one during rotation. */
const decryptSession = (token: string | Redacted.Redacted<string>, current: Uint8Array, previous: Uint8Array) =>
  JsonWebToken.decrypt(token, current, { schema: Session }).pipe(
    Effect.catchTag("DecryptionError", () => JsonWebToken.decrypt(token, previous, { schema: Session })),
    Effect.map(({ payload }) => payload)
  )

export const main = Effect.gen(function*() {
  const previous = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const current = globalThis.crypto.getRandomValues(new Uint8Array(32))

  // A session issued before the rotation, and one after.
  const before = yield* encryptSession(previous, { sub: "user-1", email: Redacted.make("one@example.com") })
  const after = yield* encryptSession(current, { sub: "user-2", email: Redacted.make("two@example.com") })

  const sessions = yield* Effect.all([
    decryptSession(before, current, previous),
    decryptSession(after, current, previous)
  ])
  console.log("decrypted:", sessions.map((s) => s.sub))
  console.log("logged session:", JSON.stringify(sessions[0])) // email shows as <redacted>
  console.log("email when needed:", Redacted.value(sessions[0].email))

  // The token itself is opaque: the claims cannot be read without the key.
  const peek = yield* Effect.flip(JsonWebToken.decodeUnverified(before))
  console.log("reading without the key:", peek._tag)

  return { subs: sessions.map((s) => s.sub), logged: JSON.stringify(sessions[0]) }
}).pipe(Effect.provide(CryptoLive))

if (import.meta.main) Effect.runPromise(main)
