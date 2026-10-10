/**
 * Runs the example and checks what it logs, so it stays correct on every
 * server runtime. (It serves HTTP, so it does not run in browsers.)
 */
import { Effect, Logger } from "effect"
import { expect, it } from "vitest"
import { main } from "../examples/http-api-bearer-auth.ts"

it("HttpApi bearer auth against a remote key set", async () => {
  const lines: Array<string> = []
  const capture = Logger.make(({ message }) => {
    lines.push((Array.isArray(message) ? message : [message]).join(" "))
  })

  await Effect.runPromise(main.pipe(Effect.provide(Logger.layer([capture]))))

  expect(lines).toEqual([
    "Signed in as user-123 (read:me, write:me)",
    "Without a token: Missing access token",
    "Rejected access token: MalformedJwsError",
    "With an invalid token: Invalid access token"
  ])
})
