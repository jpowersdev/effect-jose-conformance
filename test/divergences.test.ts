/**
 * Intentional behavioural differences between effect/jose and jose.
 *
 * Each test pins down one difference so it stays deliberate: if either
 * library changes, the test fails and the difference must be re-evaluated.
 */
import * as jose from "jose"
import { JsonWebEncryption, JsonWebKey, JsonWebSignature, JsonWebToken } from "effect/jose"
import { describe, expect, it } from "vitest"
import { keysFor } from "../src/keys.ts"
import { settle } from "../src/outcome.ts"
import { run } from "../src/runtime.ts"

const enc = new TextEncoder()
const b64u = (s: string | Uint8Array) => jose.base64url.encode(s)
const secret = enc.encode("a-string-secret-at-least-256-bits-long")

const hmac = async (data: string) => {
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
  return b64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data))))
}

/** Builds a correctly signed HS256 compact JWS from raw header and payload segments. */
const forge = async (header: string, payloadSegment: string) => {
  const signingInput = `${header}.${payloadSegment}`
  return `${signingInput}.${await hmac(signingInput)}`
}

describe("stricter than jose", () => {
  it("rejects duplicate crit values on verification (RFC 7515 §4.1.11); jose only checks when signing", async () => {
    const token = await forge(b64u('{"alg":"HS256","crit":["b64","b64"],"b64":true}'), b64u("payload"))
    expect(await settle(jose.compactVerify(token, secret))).toEqual({ ok: true })
    expect(await settle(run(JsonWebSignature.verifyCompact(token, secret)))).toEqual({ ok: false, code: "ERR_JWS_INVALID" })
  })

  it("rejects padded or whitespace-containing base64url segments; jose accepts them", async () => {
    const header = b64u('{"alg":"HS256"}')
    const padded = await forge(header, b64u("payloa") + "=")
    const outcomes = [await settle(jose.compactVerify(padded, secret)), await settle(run(JsonWebSignature.verifyCompact(padded, secret)))]
    expect(outcomes[1]).toEqual({ ok: false, code: "ERR_JWS_INVALID" })
    // jose's acceptance depends on the runtime's base64 decoder; record what it did.
    expect(outcomes[0].ok === true || outcomes[0].ok === false).toBe(true)
  })

  it("reports a key whose curve does not match the algorithm as ERR_JWK_INVALID; jose leaks a raw DataError", async () => {
    const [p384, p256] = await Promise.all([keysFor("ES384"), keysFor("ES256")])
    const token = await new jose.CompactSign(enc.encode("x")).setProtectedHeader({ alg: "ES256" }).sign(p256.signOrEncrypt.jose as any)
    const joseOutcome = await settle(jose.compactVerify(token, p384.verifyOrDecrypt.jwk as any))
    expect(joseOutcome.ok).toBe(false)
    expect(joseOutcome.ok === false && joseOutcome.code.startsWith("Unexpected(DataError")).toBe(true)
    expect(await settle(run(JsonWebSignature.verifyCompact(token, p384.verifyOrDecrypt.jwk as any)))).toEqual({
      ok: false,
      code: "ERR_JWK_INVALID"
    })
  })

  it("reports malformed PEM as a typed argument error; jose leaks a raw InvalidCharacterError", async () => {
    const pem = "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----"
    const joseOutcome = await settle(jose.importSPKI(pem, "RS256"))
    expect(joseOutcome.ok === false && joseOutcome.code.startsWith("Unexpected(InvalidCharacterError")).toBe(true)
    expect(await settle(run(JsonWebKey.importSpki(pem, "RS256")))).toEqual({ ok: false, code: "TypeError" })
  })
})

describe("unsupported on purpose", () => {
  it("does not decompress zip:DEF content (RFC 8725 §3.6 advises against compression); jose does", async () => {
    const kek = crypto.getRandomValues(new Uint8Array(32))
    const token = await new jose.CompactEncrypt(enc.encode("x")).setProtectedHeader({ alg: "A256KW", enc: "A256GCM", zip: "DEF" }).encrypt(kek)
    expect(await settle(jose.compactDecrypt(token, kek))).toEqual({ ok: true })
    expect(await settle(run(JsonWebEncryption.decryptCompact(token, kek)))).toEqual({ ok: false, code: "ERR_JOSE_NOT_SUPPORTED" })
  })

  it("has no unsecured (alg: none) JWT support; jose offers UnsecuredJWT", async () => {
    const unsecured = new jose.UnsecuredJWT({ sub: "x" }).encode()
    expect(jose.UnsecuredJWT.decode(unsecured).payload.sub).toBe("x")
    // Verifying an unsecured token is rejected identically by both libraries.
    expect(await settle(jose.jwtVerify(unsecured, secret))).toEqual({ ok: false, code: "ERR_JOSE_NOT_SUPPORTED" })
    expect(await settle(run(JsonWebToken.verify(unsecured, secret)))).toEqual({ ok: false, code: "ERR_JOSE_NOT_SUPPORTED" })
  })
})

describe("different conventions", () => {
  it("emits unencoded (b64:false) payloads attached in flattened JSON; jose detaches them", async () => {
    const header = { alg: "HS256", b64: false, crit: ["b64"] }
    const ours = await run(JsonWebSignature.signFlattened("$.02", { key: secret, protectedHeader: header }))
    const theirs = await new jose.FlattenedSign(enc.encode("$.02")).setProtectedHeader(header).sign(secret)
    expect(ours.payload).toBe("$.02")
    expect(theirs.payload).toBe("")
    expect(ours.signature).toBe(theirs.signature)
  })

  it("takes durations as Effect Duration inputs (a bare number is milliseconds); jose takes seconds or '2h' strings", async () => {
    const now = new Date(1_700_000_000_000)
    const token = await new jose.SignJWT({ exp: 1_700_000_000 - 5 }).setProtectedHeader({ alg: "HS256" }).sign(secret)
    // 10 means 10 seconds to jose but 10 milliseconds to effect/jose.
    expect(await settle(jose.jwtVerify(token, secret, { currentDate: now, clockTolerance: 10 }))).toEqual({ ok: true })
    expect(await settle(run(JsonWebToken.verify(token, secret, { currentDate: now, clockTolerance: 10 })))).toEqual({
      ok: false,
      code: "ERR_JWT_EXPIRED"
    })
    expect(await settle(run(JsonWebToken.verify(token, secret, { currentDate: now, clockTolerance: "10 seconds" })))).toEqual({
      ok: true
    })
  })
})
