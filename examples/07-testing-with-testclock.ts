/**
 * # Testing token expiry with TestClock
 *
 * Every time check (`exp`, `nbf`, `iat`, `maxTokenAge`) and every relative time
 * when issuing (`expirationTime: "15 minutes"`) goes through Effect's `Clock`.
 * Under `TestClock`, tests move time forward instead of waiting.
 *
 * In a test suite, use `it.effect` from `@effect/vitest`, which provides
 * `TestClock` automatically.
 */
import * as Effect from "effect/Effect"
import * as TestClock from "effect/testing/TestClock"
import { JsonWebToken } from "effect/jose"
import { CryptoLive } from "./CryptoLive.ts"

const secret = new TextEncoder().encode("a-test-secret-that-is-at-least-32-bytes")

export const main = Effect.gen(function*() {
  yield* TestClock.setTime(Date.parse("2026-01-01T00:00:00Z"))

  const token = yield* JsonWebToken.sign({ sub: "user-1" }, {
    key: secret,
    protectedHeader: { alg: "HS256" },
    issuedAt: true,
    expirationTime: "15 minutes"
  })
  const check = Effect.match(JsonWebToken.verify(token, secret, { algorithms: ["HS256"] }), {
    onFailure: (error) => error._tag,
    onSuccess: () => "valid"
  })

  const atIssue = yield* check
  yield* TestClock.adjust("14 minutes")
  const beforeExpiry = yield* check
  yield* TestClock.adjust("1 minute")
  const atExpiry = yield* check

  console.log("at issue:", atIssue)
  console.log("after 14 minutes:", beforeExpiry)
  console.log("after 15 minutes:", atExpiry)
  return { atIssue, beforeExpiry, atExpiry }
}).pipe(Effect.provide([CryptoLive, TestClock.layer()]))

if (import.meta.main) Effect.runPromise(main)
