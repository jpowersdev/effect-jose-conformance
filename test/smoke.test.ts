import * as jose from "jose"
import { JsonWebSignature } from "effect/jose"
import { describe, expect, it } from "vitest"
import { run } from "../src/runtime.ts"

const secret = new TextEncoder().encode("a-string-secret-at-least-256-bits-long")

describe("smoke", () => {
  it("effect signs, jose verifies (HS256)", async () => {
    const jws = await run(JsonWebSignature.signCompact("hello", { key: secret, protectedHeader: { alg: "HS256" } }))
    const out = await jose.compactVerify(jws, secret)
    expect(new TextDecoder().decode(out.payload)).toBe("hello")
  })
  it("jose signs, effect verifies (ES256)", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true })
    const jws = await new jose.CompactSign(new TextEncoder().encode("hi")).setProtectedHeader({ alg: "ES256" }).sign(privateKey)
    const jwk = await jose.exportJWK(publicKey)
    const out = await run(JsonWebSignature.verifyCompact(jws, jwk as any))
    expect(new TextDecoder().decode(out.payload)).toBe("hi")
  })
})
