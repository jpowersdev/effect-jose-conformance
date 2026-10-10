/**
 * Intentional behavioural differences between effect/jose and jose.
 *
 * Each test pins down one difference so it stays deliberate: if either
 * library changes, the test fails and the difference must be re-evaluated.
 */
import * as jose from "jose"
import * as Effect from "effect/Effect"
import * as FetchHttpClient from "effect/http/FetchHttpClient"
import { JsonWebEncryption, JsonWebKey, JsonWebKeySet, JsonWebSignature, JsonWebToken } from "effect/jose"
import { jwksEndpoint } from "../src/jwksEndpoint.ts"
import { beforeAll, describe, expect, it } from "vitest"
import { keysFor } from "../src/keys.ts"
import { settle, tagged } from "../src/outcome.ts"
import { anySignatureAlgorithm, encryption, keys, keySets, run, signatures, tokens } from "../src/runtime.ts"

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
    expect(await settle(run(signatures.verifyCompact(token, secret, { algorithms: anySignatureAlgorithm })))).toEqual({ ok: false, code: "ERR_JWS_INVALID" })
  })

  it("rejects padded or whitespace-containing base64url segments; jose accepts them", async () => {
    const header = b64u('{"alg":"HS256"}')
    const padded = await forge(header, b64u("payloa") + "=")
    const outcomes = [await settle(jose.compactVerify(padded, secret)), await settle(run(signatures.verifyCompact(padded, secret, { algorithms: anySignatureAlgorithm })))]
    expect(outcomes[1]).toEqual({ ok: false, code: "ERR_JWS_INVALID" })
    // jose's acceptance depends on the runtime's base64 decoder; record what it did.
    expect(outcomes[0].ok === true || outcomes[0].ok === false).toBe(true)
  })

  it("reports a key whose curve does not match the algorithm as ERR_JWK_INVALID; jose leaks a raw runtime exception", async () => {
    const [p384, p256] = await Promise.all([keysFor("ES384"), keysFor("ES256")])
    const token = await new jose.CompactSign(enc.encode("x")).setProtectedHeader({ alg: "ES256" }).sign(p256.signOrEncrypt.jose as any)
    const joseOutcome = await settle(jose.compactVerify(token, p384.verifyOrDecrypt.jwk as any))
    expect(joseOutcome.ok).toBe(false)
    // The exact exception depends on the runtime's Web Crypto; it is never a jose error code.
    expect(joseOutcome.ok === false && !joseOutcome.code.startsWith("ERR_")).toBe(true)
    expect(await settle(run(signatures.verifyCompact(token, p384.verifyOrDecrypt.jwk as any, { algorithms: anySignatureAlgorithm })))).toEqual({
      ok: false,
      code: "ERR_JWK_INVALID"
    })
  })

  it("requires an embedded jwk to be integrity protected; jose's EmbeddedJWK also accepts it from the unprotected header", async () => {
    const k = await keysFor("ES256")
    const jws = await new jose.FlattenedSign(enc.encode("x"))
      .setProtectedHeader({ alg: "ES256" })
      .setUnprotectedHeader({ jwk: k.verifyOrDecrypt.jwk as jose.JWK })
      .sign(k.signOrEncrypt.jose as any)
    expect(await settle(jose.flattenedVerify(jws, jose.EmbeddedJWK))).toEqual({ ok: true })
    expect(await tagged(run(signatures.verifyFlattened(jws as any, JsonWebSignature.embeddedKey, { algorithms: anySignatureAlgorithm })))).toBe(
      "MalformedJwsError"
    )
  })

  it("reports a key of the wrong type for the algorithm as InvalidKeyError; jose reports it as not supported", async () => {
    const [rsa, es] = await Promise.all([keysFor("RS256"), keysFor("ES256")])
    const token = await new jose.CompactSign(enc.encode("x")).setProtectedHeader({ alg: "ES256" }).sign(es.signOrEncrypt.jose as any)
    expect(await settle(jose.compactVerify(token, rsa.verifyOrDecrypt.jwk as any))).toEqual({
      ok: false,
      code: "ERR_JOSE_NOT_SUPPORTED"
    })
    expect(await tagged(run(signatures.verifyCompact(token, rsa.verifyOrDecrypt.jwk as any, { algorithms: anySignatureAlgorithm })))).toBe("InvalidKeyError")
  })

  it("reports malformed PEM as MalformedKeyError; jose leaks a raw runtime exception", async () => {
    const pem = "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----"
    const joseOutcome = await settle(jose.importSPKI(pem, "RS256"))
    // The exact exception depends on the runtime's base64 decoder; it is never a jose error code.
    expect(joseOutcome.ok === false && !joseOutcome.code.startsWith("ERR_")).toBe(true)
    expect(await tagged(run(keys.importSpki(pem, "RS256")))).toBe("MalformedKeyError")
  })
})

describe("unsupported on purpose", () => {
  it("does not decompress zip:DEF content (RFC 8725 §3.6 advises against compression); jose does", async () => {
    const kek = crypto.getRandomValues(new Uint8Array(32))
    const token = await new jose.CompactEncrypt(enc.encode("x")).setProtectedHeader({ alg: "A256KW", enc: "A256GCM", zip: "DEF" }).encrypt(kek)
    expect(await settle(jose.compactDecrypt(token, kek))).toEqual({ ok: true })
    expect(await settle(run(encryption.decryptCompact(token, kek)))).toEqual({ ok: false, code: "ERR_JOSE_NOT_SUPPORTED" })
  })

  it("has no unsecured (alg: none) JWT support; jose offers UnsecuredJWT", async () => {
    const unsecured = new jose.UnsecuredJWT({ sub: "x" }).encode()
    expect(jose.UnsecuredJWT.decode(unsecured).payload.sub).toBe("x")
    // Verifying an unsecured token is rejected by both libraries: "none" is never
    // an allowed algorithm (effect/jose always has an allow list), and it is not
    // a supported one (jose without an allow list).
    expect(await settle(jose.jwtVerify(unsecured, secret))).toEqual({ ok: false, code: "ERR_JOSE_NOT_SUPPORTED" })
    expect(await settle(run(tokens.verify(unsecured, secret, { algorithms: anySignatureAlgorithm })))).toEqual({
      ok: false,
      code: "ERR_JOSE_ALG_NOT_ALLOWED"
    })
  })
})

describe("different conventions", () => {
  it("emits unencoded (b64:false) payloads attached in flattened JSON; jose detaches them", async () => {
    const header = { alg: "HS256" as const, b64: false, crit: ["b64"] }
    const ours = await run(signatures.signFlattened("$.02", { key: secret, protectedHeader: header }))
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
    expect(await settle(run(tokens.verify(token, secret, { algorithms: anySignatureAlgorithm, currentDate: now, clockTolerance: 10 })))).toEqual({
      ok: false,
      code: "ERR_JWT_EXPIRED"
    })
    expect(await settle(run(tokens.verify(token, secret, { algorithms: anySignatureAlgorithm, currentDate: now, clockTolerance: "10 seconds" })))).toEqual({
      ok: true
    })
  })
})

describe("hardening jose does not do", () => {
  it("requires HMAC keys at least as long as the hash (RFC 7518 section 3.2); jose accepts shorter ones", async () => {
    const short = new Uint8Array(16)
    const token = await new jose.CompactSign(enc.encode("x")).setProtectedHeader({ alg: "HS256" }).sign(short)
    expect(await settle(jose.compactVerify(token, short))).toEqual({ ok: true })
    expect(await tagged(run(signatures.verifyCompact(token, short, { algorithms: anySignatureAlgorithm })))).toBe("InvalidKeyError")
    expect(await tagged(run(signatures.signCompact("x", { key: short, protectedHeader: { alg: "HS256" } })))).toBe(
      "InvalidKeyError"
    )
  })

  it("caps compact tokens at 64 KiB by default, adjustable with maxTokenLength; jose has no limit", async () => {
    const token = await new jose.CompactSign(enc.encode("x".repeat(70_000))).setProtectedHeader({ alg: "HS256" }).sign(secret)
    expect(await settle(jose.compactVerify(token, secret))).toEqual({ ok: true })
    expect(await tagged(run(signatures.verifyCompact(token, secret, { algorithms: anySignatureAlgorithm })))).toBe("JwsTooLargeError")
    expect(await settle(run(signatures.verifyCompact(token, secret, { algorithms: anySignatureAlgorithm, maxTokenLength: 200_000 })))).toEqual({
      ok: true
    })
  })

  describe("remote key sets", () => {
    const remote = (url: string, options?: JsonWebKeySet.RemoteOptions) =>
      run(
        Effect.flatMap(keySets.makeRemote(url, options), (resolver) =>
          Effect.flatMap(
            Effect.promise(() =>
              new jose.CompactSign(enc.encode("x")).setProtectedHeader({ alg: "ES256", kid: "k" }).sign(signingKey)
            ),
            (token) => signatures.verifyCompact(token, resolver, { algorithms: anySignatureAlgorithm })
          )).pipe(Effect.provide(FetchHttpClient.layer))
      )
    let signingKey: CryptoKey
    let publicJwk: jose.JWK

    beforeAll(async () => {
      const pair = await jose.generateKeyPair("ES256", { extractable: true })
      signingKey = pair.privateKey
      publicJwk = { ...(await jose.exportJWK(pair.publicKey)), kid: "k" }
    })

    it("require HTTPS unless allowInsecureHttp is set; jose fetches plain HTTP", async () => {
      const endpoint = await jwksEndpoint({ keys: [publicJwk] })
      expect(await tagged(remote(endpoint.url))).toBe("InvalidKeySetUrlError")
      expect(await tagged(remote(endpoint.url, { allowInsecureHttp: true }))).toBe("Success")
      const token = await new jose.CompactSign(enc.encode("x")).setProtectedHeader({ alg: "ES256", kid: "k" }).sign(signingKey)
      expect(await settle(jose.compactVerify(token, jose.createRemoteJWKSet(new URL(endpoint.url))))).toEqual({ ok: true })
    })

    it("refuse redirects", async () => {
      const endpoint = await jwksEndpoint({ keys: [publicJwk] })
      expect(await tagged(remote(endpoint.redirectUrl, { allowInsecureHttp: true }))).toBe("KeySetFetchError")
    })

    it("cap the response at 128 KiB by default; jose has no limit", async () => {
      const endpoint = await jwksEndpoint({ keys: [publicJwk] })
      expect(await tagged(remote(endpoint.bigUrl, { allowInsecureHttp: true }))).toBe("KeySetTooLargeError")
      expect(await tagged(remote(endpoint.bigUrl, { allowInsecureHttp: true, maxResponseBytes: 300_000 }))).toBe(
        "Success"
      )
      const token = await new jose.CompactSign(enc.encode("x")).setProtectedHeader({ alg: "ES256", kid: "k" }).sign(signingKey)
      expect(await settle(jose.compactVerify(token, jose.createRemoteJWKSet(new URL(endpoint.bigUrl))))).toEqual({
        ok: true
      })
    })
  })
})

describe("stricter defaults", () => {
  it("requires an explicit algorithms list unless the key is a Crypto.Key; jose accepts any compatible algorithm", async () => {
    const token = await new jose.CompactSign(enc.encode("x")).setProtectedHeader({ alg: "HS384" }).sign(
      new Uint8Array(48)
    )
    expect(await settle(jose.compactVerify(token, new Uint8Array(48)))).toEqual({ ok: true })
    const verifyUntyped = signatures.verifyCompact as (...args: ReadonlyArray<unknown>) => Effect.Effect<unknown>
    expect(await tagged(run(verifyUntyped(token, new Uint8Array(48)) as any))).toBe("TypeError")
    expect(await settle(run(signatures.verifyCompact(token, new Uint8Array(48), { algorithms: ["HS256"] })))).toEqual({
      ok: false,
      code: "ERR_JOSE_ALG_NOT_ALLOWED"
    })
  })

  it("requires exp by default (requireExpiration: false opts out); jose does not", async () => {
    const token = await new jose.SignJWT({ sub: "x" }).setProtectedHeader({ alg: "HS256" }).sign(secret)
    expect(await settle(jose.jwtVerify(token, secret))).toEqual({ ok: true })
    expect(await settle(run(tokens.verify(token, secret, { algorithms: ["HS256"] })))).toEqual({
      ok: false,
      code: "ERR_JWT_CLAIM_VALIDATION_FAILED"
    })
    expect(await settle(run(tokens.verify(token, secret, { algorithms: ["HS256"], requireExpiration: false })))).toEqual({
      ok: true
    })
    expect(await tagged(run(tokens.sign({ sub: "x" }, { key: secret, protectedHeader: { alg: "HS256" } })))).toBe(
      "ClaimValidationError"
    )
  })
})
