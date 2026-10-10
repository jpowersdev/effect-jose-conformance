/** Runs every example, so the examples stay correct on every runtime. */
import * as Effect from "effect/Effect"
import { describe, expect, it } from "vitest"
import * as SessionTokens from "../examples/01-session-tokens.ts"
import * as BearerAuth from "../examples/02-http-api-bearer-auth.ts"
import * as IdentityProvider from "../examples/03-identity-provider-tokens.ts"
import * as KeyRotation from "../examples/04-publish-jwks-and-rotate-keys.ts"
import * as ServiceToService from "../examples/05-service-to-service.ts"
import * as EncryptedTokens from "../examples/06-encrypted-tokens.ts"
import * as Testing from "../examples/07-testing-with-testclock.ts"

describe("examples", () => {
  it("01 session tokens", async () => {
    const result = await Effect.runPromise(SessionTokens.main)
    expect(result.session).toMatchObject({ sub: "user-123", role: "admin" })
    expect(result.error).toBe("SignatureVerificationError")
  })

  it("02 HttpApi bearer auth", async () => {
    const result = await Effect.runPromise(BearerAuth.main)
    expect(result).toEqual({
      ok: 200,
      okBody: { id: "user-123", scopes: ["read:me"] },
      missing: 401,
      forged: 401
    })
  })

  it("03 identity provider tokens", async () => {
    const result = await Effect.runPromise(IdentityProvider.main)
    expect(result).toEqual({ sub: "auth0|123", fetches: 1 })
  })

  it("04 publish a key set and rotate keys", async () => {
    const result = await Effect.runPromise(KeyRotation.main)
    expect(result).toEqual({ verified: ["alice", "bob"], retired: "NoMatchingKeyError" })
  })

  it("05 service to service", async () => {
    const result = await Effect.runPromise(ServiceToService.main)
    expect(result).toEqual({ caller: "orders-service", wrongAudience: "ClaimValidationError" })
  })

  it("06 encrypted tokens", async () => {
    const result = await Effect.runPromise(EncryptedTokens.main)
    expect(result.subs).toEqual(["user-1", "user-2"])
    expect(result.logged).toContain('"email":"<redacted>"')
  })

  it("07 testing with TestClock", async () => {
    const result = await Effect.runPromise(Testing.main)
    expect(result).toEqual({ atIssue: "valid", beforeExpiry: "valid", atExpiry: "TokenExpiredError" })
  })
})
