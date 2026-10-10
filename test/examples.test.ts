/** Runs the example, so it stays correct on every runtime. */
import * as Effect from "effect/Effect"
import { expect, it } from "vitest"
import * as BearerAuth from "../examples/http-api-bearer-auth.ts"

it("HttpApi bearer auth against a remote key set", async () => {
  expect(await Effect.runPromise(BearerAuth.main)).toEqual({
    user: { id: "user-123", scopes: ["read:me", "write:me"] },
    anonymous: "Unauthorized",
    forged: "Unauthorized"
  })
})
