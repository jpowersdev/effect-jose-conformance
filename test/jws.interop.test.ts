import * as jose from "jose"
import { JsonWebKey, JsonWebSignature } from "effect/jose"
import { describe, expect, it } from "vitest"
import { keysFor } from "../src/keys.ts"
import { run, runToken, anySignatureAlgorithm } from "../src/runtime.ts"

const algorithms = [
  "HS256", "HS384", "HS512",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "ES256", "ES384", "ES512",
  "EdDSA", "Ed25519"
] as const

const payload = new TextEncoder().encode(JSON.stringify({ hello: "world", n: 42, unicode: "héllo ✓" }))
const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes)

describe.each(algorithms)("JWS %s", (alg) => {
  it("effect signs (compact) → jose verifies", async () => {
    const keys = await keysFor(alg)
    const jws = await runToken(JsonWebSignature.signCompact(payload, {
      key: keys.signOrEncrypt.jwk as any,
      protectedHeader: { alg, kid: "k1" }
    }))
    const verified = await jose.compactVerify(jws, keys.verifyOrDecrypt.jose as any, { algorithms: [alg] })
    expect(decode(verified.payload)).toBe(decode(payload))
    expect(verified.protectedHeader).toEqual({ alg, kid: "k1" })
  })

  it("jose signs (compact) → effect verifies", async () => {
    const keys = await keysFor(alg)
    const jws = await new jose.CompactSign(payload).setProtectedHeader({ alg, typ: "JOSE" }).sign(
      keys.signOrEncrypt.jose as any
    )
    const verified = await run(JsonWebSignature.verifyCompact(jws, keys.verifyOrDecrypt.jwk as any, { algorithms: [alg] }))
    expect(decode(verified.payload)).toBe(decode(payload))
    expect(verified.protectedHeader).toEqual({ alg, typ: "JOSE" })
  })

  it("effect signs with an imported Crypto.Key → jose verifies", async () => {
    const keys = await keysFor(alg)
    const key = keys.signOrEncrypt.jwk instanceof Uint8Array
      ? keys.signOrEncrypt.jwk
      : await run(JsonWebKey.importJwk(keys.signOrEncrypt.jwk as any, alg))
    const jws = await runToken(JsonWebSignature.signCompact(payload, { key, protectedHeader: { alg } }))
    await jose.compactVerify(jws, keys.verifyOrDecrypt.jose as any)
  })

  it("flattened JSON with protected + unprotected headers round-trips both ways", async () => {
    const keys = await keysFor(alg)
    const ours = await run(JsonWebSignature.signFlattened(payload, {
      key: keys.signOrEncrypt.jwk as any,
      protectedHeader: { alg },
      unprotectedHeader: { kid: "u1" }
    }))
    const theirs = await jose.flattenedVerify(ours as any, keys.verifyOrDecrypt.jose as any)
    expect(theirs.unprotectedHeader).toEqual({ kid: "u1" })
    const joseJws = await new jose.FlattenedSign(payload).setProtectedHeader({ alg }).setUnprotectedHeader({
      kid: "u2"
    }).sign(keys.signOrEncrypt.jose as any)
    const verified = await run(JsonWebSignature.verifyFlattened(joseJws as any, keys.verifyOrDecrypt.jwk as any, { algorithms: anySignatureAlgorithm }))
    expect(verified.unprotectedHeader).toEqual({ kid: "u2" })
  })

  it("unencoded payload (RFC 7797, b64:false) round-trips both ways", async () => {
    const keys = await keysFor(alg)
    const header = { alg, b64: false, crit: ["b64"] }
    const ours = await run(JsonWebSignature.signFlattened("$.02", { key: keys.signOrEncrypt.jwk as any, protectedHeader: header }))
    expect(ours.payload).toBe("$.02")
    await jose.flattenedVerify(ours as any, keys.verifyOrDecrypt.jose as any)
    const joseJws = await new jose.FlattenedSign(new TextEncoder().encode("$.02")).setProtectedHeader(header).sign(
      keys.signOrEncrypt.jose as any
    )
    // jose emits unencoded payloads detached (payload: ""); supply it for verification.
    expect(joseJws.payload).toBe("")
    const verified = await run(
      JsonWebSignature.verifyFlattened({ ...joseJws, payload: "$.02" } as any, keys.verifyOrDecrypt.jwk as any, { algorithms: anySignatureAlgorithm })
    )
    expect(decode(verified.payload)).toBe("$.02")
  })
})

describe("JWS general JSON serialization", () => {
  it("multiple signers (HS256 + ES256 + EdDSA) interoperate both ways", async () => {
    const [hs, es, ed] = await Promise.all([keysFor("HS256"), keysFor("ES256"), keysFor("EdDSA")])
    const ours = await run(JsonWebSignature.signGeneral(payload, [
      { key: hs.signOrEncrypt.jwk as any, protectedHeader: { alg: "HS256" } },
      { key: es.signOrEncrypt.jwk as any, protectedHeader: { alg: "ES256" }, unprotectedHeader: { kid: "es" } },
      { key: ed.signOrEncrypt.jwk as any, protectedHeader: { alg: "EdDSA" } }
    ]))
    expect(ours.signatures).toHaveLength(3)
    for (const k of [hs, es, ed]) await jose.generalVerify(ours as any, k.verifyOrDecrypt.jose as any)

    const sign = new jose.GeneralSign(payload)
    sign.addSignature(hs.signOrEncrypt.jose as any).setProtectedHeader({ alg: "HS256" })
    sign.addSignature(es.signOrEncrypt.jose as any).setProtectedHeader({ alg: "ES256" })
    sign.addSignature(ed.signOrEncrypt.jose as any).setProtectedHeader({ alg: "EdDSA" })
    const theirs = await sign.sign()
    for (const k of [hs, es, ed]) await run(JsonWebSignature.verifyGeneral(theirs as any, k.verifyOrDecrypt.jwk as any, { algorithms: anySignatureAlgorithm }))
  })
})
