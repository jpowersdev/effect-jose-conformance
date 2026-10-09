import * as Redacted from "effect/Redacted"
import * as jose from "jose"
import { JsonWebKey, JsonWebSignature, JsonWebEncryption } from "effect/jose"
import { describe, expect, it } from "vitest"
import { keysFor } from "../src/keys.ts"
import { settle } from "../src/outcome.ts"
import { run, runToken } from "../src/runtime.ts"

const payload = new TextEncoder().encode("payload")

describe("RFC 7638 thumbprints match jose", () => {
  const algs = ["RS256", "ES256", "ES384", "ES512", "EdDSA", "ECDH-ES"] as const
  it.each(algs)("%s public and private JWKs", async (alg) => {
    const keys = await keysFor(alg)
    for (const jwk of [keys.signOrEncrypt.jwk, keys.verifyOrDecrypt.jwk] as Array<jose.JWK>) {
      for (const digest of ["sha256", "sha384", "sha512"] as const) {
        expect(await run(JsonWebKey.thumbprint(jwk as any, digest))).toBe(await jose.calculateJwkThumbprint(jwk, digest))
        expect(await run(JsonWebKey.thumbprintUri(jwk as any, digest))).toBe(await jose.calculateJwkThumbprintUri(jwk, digest))
      }
    }
  })

  it("oct key and the RFC 7638 §3.1 example", async () => {
    const octJwk = { kty: "oct", k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow" }
    expect(await run(JsonWebKey.thumbprint(octJwk))).toBe(await jose.calculateJwkThumbprint(octJwk))
    const rfc = {
      kty: "RSA",
      n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      e: "AQAB",
      alg: "RS256",
      kid: "2011-04-29"
    }
    expect(await run(JsonWebKey.thumbprint(rfc))).toBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
  })

  it("missing members fail like jose", async () => {
    for (const jwk of [{ kty: "EC", crv: "P-256", x: "AA" }, { kty: "RSA", e: "AQAB" }, { kty: "OKP" }, { kty: "nope" }]) {
      expect(await settle(run(JsonWebKey.thumbprint(jwk as any)))).toEqual(await settle(jose.calculateJwkThumbprint(jwk as any)))
    }
  })
})

describe("PEM import and export interoperate with jose", () => {
  const algs = ["RS256", "PS384", "ES256", "ES512", "EdDSA", "RSA-OAEP-256", "ECDH-ES"] as const
  it.each(algs)("%s: jose exports PEM → effect imports and uses it; effect exports PEM → jose imports it", async (alg) => {
    const { publicKey, privateKey } = await jose.generateKeyPair(alg, { extractable: true })
    const spki = await jose.exportSPKI(publicKey)
    const pkcs8 = await jose.exportPKCS8(privateKey)
    const pub = await run(JsonWebKey.importSpki(spki, alg))
    const priv = await run(JsonWebKey.importPkcs8(pkcs8, alg, { extractable: true }))
    expect(pub.type).toBe("public")
    expect(priv.type).toBe("private")
    expect(await run(JsonWebKey.exportSpki(pub))).toBe(spki)
    expect(Redacted.value(await run(JsonWebKey.exportPkcs8(priv)))).toBe(pkcs8)
    if (alg === "RSA-OAEP-256" || alg === "ECDH-ES") {
      const jwe = await runToken(JsonWebEncryption.encryptCompact(payload, { key: pub, protectedHeader: { alg, enc: "A128GCM" } }))
      await jose.compactDecrypt(jwe, await jose.importPKCS8(Redacted.value(await run(JsonWebKey.exportPkcs8(priv))), alg))
    } else {
      const jws = await runToken(JsonWebSignature.signCompact(payload, { key: priv, protectedHeader: { alg } }))
      await jose.compactVerify(jws, await jose.importSPKI(await run(JsonWebKey.exportSpki(pub)), alg))
    }
  })

  it("ECDH-ES detects the curve from the SPKI", async () => {
    for (const crv of ["P-256", "P-384", "P-521", "X25519"]) {
      const { publicKey } = await jose.generateKeyPair("ECDH-ES", { crv, extractable: true })
      const key = await run(JsonWebKey.importSpki(await jose.exportSPKI(publicKey), "ECDH-ES"))
      expect(key.algorithm.name === "X25519" ? "X25519" : key.algorithm.namedCurve).toBe(crv)
    }
  })
})

describe("key generation produces keys jose accepts", () => {
  const pairs = ["RS256", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"] as const
  it.each(pairs)("generateKeyPair(%s) signs tokens jose verifies", async (alg) => {
    const { privateKey, publicKey } = await run(JsonWebKey.generateKeyPair(alg, { extractable: true }))
    const jws = await runToken(JsonWebSignature.signCompact(payload, { key: privateKey, protectedHeader: { alg } }))
    const jwk = await run(JsonWebKey.exportJwk(publicKey))
    await jose.compactVerify(jws, jwk as jose.JWK)
    expect(privateKey.extractable).toBe(true)
  })

  it("generateKeyPair defaults to non-extractable private keys", async () => {
    const { privateKey } = await run(JsonWebKey.generateKeyPair("ES256"))
    expect(privateKey.extractable).toBe(false)
    expect(await settle(run(JsonWebKey.exportJwk(privateKey)))).toEqual({ ok: false, code: "TypeError" })
  })

  it("rejects RSA modulus below 2048 like jose", async () => {
    expect(await settle(run(JsonWebKey.generateKeyPair("RS256", { modulusLength: 1024 })))).toEqual(
      await settle(jose.generateKeyPair("RS256", { modulusLength: 1024 }))
    )
  })

  const secrets = ["HS256", "HS512", "A128KW", "A256KW", "A256GCMKW", "A128GCM", "A256CBC-HS512"] as const
  it.each(secrets)("generateSecret(%s) has the size jose expects", async (alg) => {
    const ours = await run(JsonWebKey.generateSecret(alg, { extractable: true }))
    const theirs = await jose.generateSecret(alg, { extractable: true })
    const ourBytes = ours instanceof Uint8Array ? ours : await run(JsonWebKey.exportPrivateJwk(ours)).then((j) => jose.base64url.decode(Redacted.value(j).k as string))
    const theirBytes = theirs instanceof Uint8Array ? theirs : jose.base64url.decode((await jose.exportJWK(theirs)).k!)
    expect(ourBytes.length).toBe(theirBytes.length)
    expect(ours instanceof Uint8Array).toBe(theirs instanceof Uint8Array)
  })

  it("ECDH-ES X25519 pairs work with jose", async () => {
    const { privateKey, publicKey } = await run(JsonWebKey.generateKeyPair("ECDH-ES", { crv: "X25519", extractable: true }))
    const pubJwk = await run(JsonWebKey.exportJwk(publicKey))
    const jwe = await new jose.CompactEncrypt(payload).setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" }).encrypt(pubJwk as jose.JWK)
    const out = await run(JsonWebEncryption.decryptCompact(jwe, privateKey))
    expect(new TextDecoder().decode(out.plaintext)).toBe("payload")
  })
})

describe("importJwk validation matches jose", () => {
  it("rejects malformed key_ops / ext and unsupported kty", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256", { extractable: true })
    const jwk = await jose.exportJWK(publicKey)
    for (const bad of [{ ...jwk, key_ops: "verify" }, { ...jwk, key_ops: ["verify", "verify"] }, { ...jwk, ext: "yes" }, { kty: "XYZ" }]) {
      expect(await settle(run(JsonWebKey.importJwk(bad as any, "ES256")))).toEqual(await settle(jose.importJWK(bad as any, "ES256")))
    }
  })

  it("oct JWKs import to raw bytes like jose", async () => {
    const jwk = { kty: "oct", k: jose.base64url.encode(new Uint8Array([1, 2, 3])) }
    expect(await run(JsonWebKey.importJwk(jwk, "HS256"))).toEqual(await jose.importJWK(jwk, "HS256"))
  })
})
