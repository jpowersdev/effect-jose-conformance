import * as jose from "jose"
import { JsonWebEncryption, JsonWebSignature } from "effect/jose"
import { describe, expect, it } from "vitest"
import { keysFor } from "../src/keys.ts"
import { settle } from "../src/outcome.ts"
import { run, runToken, anySignatureAlgorithm } from "../src/runtime.ts"

const enc = new TextEncoder()
const b64u = (s: string | Uint8Array) => jose.base64url.encode(s)
const payload = enc.encode("payload")
const secret = enc.encode("a-string-secret-at-least-256-bits-long")

/** Asserts both libraries reach the same outcome (success, or the same error code). */
const same = async (joseOp: () => Promise<unknown>, effectOp: () => Promise<unknown>) => {
  const [a, b] = await Promise.all([settle(joseOp()), settle(effectOp())])
  expect(b).toEqual(a)
  return a
}

const hs256 = () => new jose.CompactSign(payload).setProtectedHeader({ alg: "HS256" }).sign(secret)

const compactCases: ReadonlyArray<readonly [string, (valid: string) => string]> = [
  ["valid token", (t) => t],
  ["two segments", (t) => t.split(".").slice(0, 2).join(".")],
  ["four segments", (t) => `${t}.x`],
  ["empty string", () => ""],
  ["tampered payload", (t) => { const [h, , s] = t.split("."); return `${h}.${b64u("other")}.${s}` }],
  ["tampered signature", (t) => { const [h, p, s] = t.split("."); return `${h}.${p}.${s.slice(0, -2)}AA` }],
  ["signature not base64url", (t) => { const [h, p] = t.split("."); return `${h}.${p}.***` }],
  ["header not base64url", (t) => { const [, p, s] = t.split("."); return `***.${p}.${s}` }],
  ["header not JSON", (t) => { const [, p, s] = t.split("."); return `${b64u("not json")}.${p}.${s}` }],
  ["header JSON array", (t) => { const [, p, s] = t.split("."); return `${b64u("[1]")}.${p}.${s}` }],
  ["header missing alg", (t) => { const [, p, s] = t.split("."); return `${b64u("{}")}.${p}.${s}` }],
  ["alg none", (t) => { const [, p] = t.split("."); return `${b64u('{"alg":"none"}')}.${p}.` }],
  ["unknown alg", (t) => { const [, p, s] = t.split("."); return `${b64u('{"alg":"HS999"}')}.${p}.${s}` }],
  ["crit not protected-array", (t) => { const [, p, s] = t.split("."); return `${b64u('{"alg":"HS256","crit":"b64"}')}.${p}.${s}` }],
  ["crit empty array", (t) => { const [, p, s] = t.split("."); return `${b64u('{"alg":"HS256","crit":[]}')}.${p}.${s}` }],
  ["crit unknown extension", (t) => { const [, p, s] = t.split("."); return `${b64u('{"alg":"HS256","crit":["exp"],"exp":1}')}.${p}.${s}` }],
  ["crit extension missing", (t) => { const [, p, s] = t.split("."); return `${b64u('{"alg":"HS256","crit":["b64"]}')}.${p}.${s}` }],
  ["b64 not boolean", (t) => { const [, p, s] = t.split("."); return `${b64u('{"alg":"HS256","crit":["b64"],"b64":"no"}')}.${p}.${s}` }]
]

describe("JWS compact verification failures match jose", () => {
  it.each(compactCases)("%s", async (_, mutate) => {
    const token = mutate(await hs256())
    // Both libraries get the same allow list of every supported algorithm.
    await same(
      () => jose.compactVerify(token, secret, { algorithms: [...anySignatureAlgorithm] }),
      () => run(JsonWebSignature.verifyCompact(token, secret, { algorithms: anySignatureAlgorithm }))
    )
  })

  it("alg allow list rejects with ERR_JOSE_ALG_NOT_ALLOWED", async () => {
    const token = await hs256()
    const outcome = await same(
      () => jose.compactVerify(token, secret, { algorithms: ["HS512"] }),
      () => run(JsonWebSignature.verifyCompact(token, secret, { algorithms: ["HS512"] }))
    )
    expect(outcome).toEqual({ ok: false, code: "ERR_JOSE_ALG_NOT_ALLOWED" })
  })

  it("custom crit extension accepted only when recognized", async () => {
    const header = { alg: "HS256", crit: ["urn:x"], "urn:x": 1 }
    const token = await new jose.CompactSign(payload).setProtectedHeader(header).sign(secret, { crit: { "urn:x": true } })
    // Both libraries get the same allow list of every supported algorithm.
    await same(
      () => jose.compactVerify(token, secret, { algorithms: [...anySignatureAlgorithm] }),
      () => run(JsonWebSignature.verifyCompact(token, secret, { algorithms: anySignatureAlgorithm }))
    )
    const ok = await same(
      () => jose.compactVerify(token, secret, { crit: { "urn:x": true } }),
      () => run(JsonWebSignature.verifyCompact(token, secret, { algorithms: anySignatureAlgorithm, crit: { "urn:x": true } }))
    )
    expect(ok).toEqual({ ok: true })
  })
})

describe("key misuse matches jose", () => {
  it("RSA key shorter than 2048 bits is rejected for RS256", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ["sign", "verify"]
    )
    const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey)
    const { key_ops: _, ext: __, alg: ___, ...privateJwk } = jwk as any
    await same(
      () => new jose.CompactSign(payload).setProtectedHeader({ alg: "RS256" }).sign(privateJwk),
      () => runToken(JsonWebSignature.signCompact(payload, { key: privateJwk, protectedHeader: { alg: "RS256" } }))
    )
  })

  it("public JWK cannot sign; private JWK cannot verify", async () => {
    const keys = await keysFor("ES256")
    await same(
      () => new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256" }).sign(keys.verifyOrDecrypt.jwk as any),
      () => runToken(JsonWebSignature.signCompact(payload, { key: keys.verifyOrDecrypt.jwk as any, protectedHeader: { alg: "ES256" } }))
    )
    const token = await new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256" }).sign(keys.signOrEncrypt.jose as any)
    await same(
      () => jose.compactVerify(token, keys.signOrEncrypt.jwk as any),
      () => run(JsonWebSignature.verifyCompact(token, keys.signOrEncrypt.jwk as any, { algorithms: anySignatureAlgorithm }))
    )
  })

  it("JWK alg / use / key_ops constraints are enforced", async () => {
    const keys = await keysFor("ES256")
    const token = await new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256" }).sign(keys.signOrEncrypt.jose as any)
    const pub = keys.verifyOrDecrypt.jwk as jose.JWK
    for (const jwk of [{ ...pub, alg: "ES384" }, { ...pub, use: "enc" }, { ...pub, key_ops: ["encrypt"] }, { ...pub, alg: "ES256", use: "sig", key_ops: ["verify"] }]) {
      await same(() => jose.compactVerify(token, jwk), () => run(JsonWebSignature.verifyCompact(token, jwk as any, { algorithms: anySignatureAlgorithm })))
    }
  })

  it("key type confusion: HMAC secret where ES256 expected; EC key with HS256 header", async () => {
    const keys = await keysFor("ES256")
    const esToken = await new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256" }).sign(keys.signOrEncrypt.jose as any)
    await same(() => jose.compactVerify(esToken, secret), () => run(JsonWebSignature.verifyCompact(esToken, secret, { algorithms: anySignatureAlgorithm })))
    // Classic algorithm-confusion attack: an HS256 token "signed" with the public key's bytes.
    const forged = await new jose.CompactSign(payload).setProtectedHeader({ alg: "HS256" }).sign(enc.encode(JSON.stringify(keys.verifyOrDecrypt.jwk)))
    const outcome = await same(
      () => jose.compactVerify(forged, keys.verifyOrDecrypt.jwk as any),
      () => run(JsonWebSignature.verifyCompact(forged, keys.verifyOrDecrypt.jwk as any, { algorithms: anySignatureAlgorithm }))
    )
    expect(outcome.ok).toBe(false)
  })
})

describe("JWE decryption failures match jose", () => {
  const encryptA256KW = async () => {
    const kek = crypto.getRandomValues(new Uint8Array(32))
    const token = await new jose.CompactEncrypt(payload).setProtectedHeader({ alg: "A256KW", enc: "A256GCM" }).encrypt(kek)
    return { kek, token }
  }

  const mutations: ReadonlyArray<readonly [string, (parts: Array<string>) => string]> = [
    ["valid", (p) => p.join(".")],
    ["four segments", (p) => p.slice(0, 4).join(".")],
    ["tampered ciphertext", (p) => { p[3] = b64u(enc.encode("xxxxxxx")); return p.join(".") }],
    ["tampered tag", (p) => { p[4] = b64u(new Uint8Array(16)); return p.join(".") }],
    ["short tag", (p) => { p[4] = b64u(new Uint8Array(8)); return p.join(".") }],
    ["tampered encrypted key", (p) => { p[1] = b64u(new Uint8Array(40)); return p.join(".") }],
    ["missing encrypted key", (p) => { p[1] = ""; return p.join(".") }],
    ["bad iv length", (p) => { p[2] = b64u(new Uint8Array(8)); return p.join(".") }],
    ["missing iv", (p) => { p[2] = ""; return p.join(".") }],
    ["header missing enc", (p) => { p[0] = b64u('{"alg":"A256KW"}'); return p.join(".") }],
    ["unknown enc", (p) => { p[0] = b64u('{"alg":"A256KW","enc":"A999GCM"}'); return p.join(".") }],
    ["unknown alg", (p) => { p[0] = b64u('{"alg":"XYZ","enc":"A256GCM"}'); return p.join(".") }],
    ["tampered protected header", (p) => { p[0] = b64u('{"alg":"A256KW","enc":"A256GCM","kid":"x"}'); return p.join(".") }]
  ]

  it.each(mutations)("%s", async (_, mutate) => {
    const { kek, token } = await encryptA256KW()
    const mutated = mutate(token.split("."))
    await same(() => jose.compactDecrypt(mutated, kek), () => run(JsonWebEncryption.decryptCompact(mutated, kek)))
  })

  it("PBES2 is rejected unless explicitly allowed, and p2c is bounded", async () => {
    const password = enc.encode("pw")
    const token = await new jose.CompactEncrypt(payload).setProtectedHeader({ alg: "PBES2-HS256+A128KW", enc: "A128GCM" })
      .setKeyManagementParameters({ p2c: 20_000 }).encrypt(password)
    await same(() => jose.compactDecrypt(token, password), () => run(JsonWebEncryption.decryptCompact(token, password)))
    const allow = { keyManagementAlgorithms: ["PBES2-HS256+A128KW" as const] }
    await same(() => jose.compactDecrypt(token, password, allow), () => run(JsonWebEncryption.decryptCompact(token, password, allow)))
    const raised = { ...allow, maxPBES2Count: 30_000 }
    const ok = await same(() => jose.compactDecrypt(token, password, raised), () => run(JsonWebEncryption.decryptCompact(token, password, raised)))
    expect(ok).toEqual({ ok: true })
  })

  it("wrong RSA private key fails like jose (no unwrap oracle)", async () => {
    const [a, b] = await Promise.all([keysFor("RSA-OAEP-256"), keysFor("RSA-OAEP-256")])
    const token = await new jose.CompactEncrypt(payload).setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
      .encrypt(a.signOrEncrypt.jose as any)
    const outcome = await same(
      () => jose.compactDecrypt(token, b.verifyOrDecrypt.jose as any),
      () => run(JsonWebEncryption.decryptCompact(token, b.verifyOrDecrypt.jwk as any))
    )
    expect(outcome).toEqual({ ok: false, code: "ERR_JWE_DECRYPTION_FAILED" })
  })

  it("enc allow list rejects", async () => {
    const { kek, token } = await encryptA256KW()
    const opts = { contentEncryptionAlgorithms: ["A128GCM" as const] }
    await same(() => jose.compactDecrypt(token, kek, opts), () => run(JsonWebEncryption.decryptCompact(token, kek, opts)))
  })

  it("ECDH-ES epk containing a private component is rejected", async () => {
    const keys = await keysFor("ECDH-ES")
    const token = await new jose.CompactEncrypt(payload).setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
      .encrypt(keys.signOrEncrypt.jose as any)
    const [h, ...rest] = token.split(".")
    const header = JSON.parse(new TextDecoder().decode(jose.base64url.decode(h)))
    header.epk.d = "AAAA"
    const bad = [b64u(JSON.stringify(header)), ...rest].join(".")
    await same(
      () => jose.compactDecrypt(bad, keys.verifyOrDecrypt.jose as any),
      () => run(JsonWebEncryption.decryptCompact(bad, keys.verifyOrDecrypt.jwk as any))
    )
  })
})
