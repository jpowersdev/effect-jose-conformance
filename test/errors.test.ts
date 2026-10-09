/**
 * Every failure kind is its own tagged error, defined in the module it
 * relates to, so callers can handle each one with `Effect.catchTag`.
 */
import * as jose from "jose"
import * as Effect from "effect/Effect"
import { JsonWebAlgorithm, JsonWebEncryption, JsonWebKey, JsonWebKeySet, JsonWebSignature, JsonWebToken } from "effect/jose"
import { describe, expect, it } from "vitest"
import { joseCodeFor, tagged } from "../src/outcome.ts"
import { run, anySignatureAlgorithm } from "../src/runtime.ts"

const secret = new TextEncoder().encode("a-string-secret-at-least-256-bits-long")

describe("error types", () => {
  it("each error class lives in its module and has a unique tag", () => {
    const classes = [
      JsonWebAlgorithm.UnsupportedAlgorithmError,
      JsonWebAlgorithm.AlgorithmNotAllowedError,
      JsonWebKey.InvalidKeyError,
      JsonWebKey.MalformedKeyError,
      JsonWebKey.UnsupportedKeyError,
      JsonWebSignature.MalformedJwsError,
      JsonWebSignature.SignatureVerificationError,
      JsonWebSignature.UnsupportedJwsHeaderError,
      JsonWebEncryption.MalformedJweError,
      JsonWebEncryption.DecryptionError,
      JsonWebEncryption.UnsupportedJweHeaderError,
      JsonWebToken.MalformedJwtError,
      JsonWebToken.ClaimValidationError,
      JsonWebToken.TokenExpiredError,
      JsonWebKeySet.MalformedKeySetError,
      JsonWebKeySet.NoMatchingKeyError,
      JsonWebKeySet.MultipleMatchingKeysError,
      JsonWebKeySet.KeySetFetchError,
      JsonWebKeySet.KeySetTimeoutError
    ]
    const tags = classes.map((Class) => new (Class as any)({ message: "", check: "missing", parameter: "alg", algorithm: "", claim: "exp", url: "" })._tag)
    expect(new Set(tags).size).toBe(classes.length)
    expect(Object.keys(joseCodeFor).sort()).toEqual([...tags].sort())
  })

  it("errors can be handled individually with catchTag", async () => {
    const token = await new jose.SignJWT({}).setProtectedHeader({ alg: "HS256" }).setExpirationTime(1).sign(secret)
    const outcome = await run(
      JsonWebToken.verify(token, secret, { algorithms: anySignatureAlgorithm }).pipe(
        Effect.as("valid"),
        Effect.catchTag("TokenExpiredError", (e) => Effect.succeed(`expired via ${e.claim}`)),
        Effect.catchTag("SignatureVerificationError", () => Effect.succeed("bad signature"))
      )
    )
    expect(outcome).toBe("expired via exp")
  })

  it("errors carry structured details", async () => {
    const token = await new jose.CompactSign(new Uint8Array()).setProtectedHeader({ alg: "HS256" }).sign(secret)
    const error = await run(Effect.flip(JsonWebSignature.verifyCompact(token, secret, { algorithms: ["ES256"] })))
    expect(error._tag).toBe("AlgorithmNotAllowedError")
    expect(error._tag === "AlgorithmNotAllowedError" && [error.parameter, error.algorithm]).toEqual(["alg", "HS256"])
    expect(await tagged(run(JsonWebSignature.verifyCompact("a.b", secret, { algorithms: anySignatureAlgorithm })))).toBe("MalformedJwsError")
  })
})
