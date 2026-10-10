import * as jose from "jose"
import { JsonWebEncryption } from "effect/jose"
import { describe, expect, it } from "vitest"
import { keysFor } from "../src/keys.ts"
import { aes192Supported, usesAes192 } from "../src/capabilities.ts"
import { settle, tagged } from "../src/outcome.ts"
import vectors from "./fixtures/aes192-vectors.json" with { type: "json" }
import { encryption, run, runToken } from "../src/runtime.ts"

const keyManagement = [
  "dir",
  "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512",
  "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
  "A128KW", "A192KW", "A256KW",
  "A128GCMKW", "A192GCMKW", "A256GCMKW",
  "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"
] as const

const contentEncryption = ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"] as const

const plaintext = new TextEncoder().encode("You can trust us to stick with you through thick and thin–to the bitter end.")
const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes)

const cases = keyManagement.flatMap((alg) => contentEncryption.map((enc) => [alg, enc] as const))

describe.each(cases)("JWE %s + %s", (alg, enc) => {
  const allow = { keyManagementAlgorithms: [alg], contentEncryptionAlgorithms: [enc] }

  // Chromium's Web Crypto has no 192-bit AES. There, both libraries must fail,
  // and effect/jose must say why with UnsupportedAlgorithmError.
  it.runIf(usesAes192(alg, enc))("fails clearly where the runtime lacks 192-bit AES", async ({ skip }) => {
    if (await aes192Supported) return skip("runtime supports 192-bit AES")
    // Asymmetric algorithms get a real key pair; symmetric ones the right-sized secret.
    const key = alg.startsWith("RSA") || alg.startsWith("ECDH")
      ? (await keysFor(alg)).signOrEncrypt.jwk
      : alg === "dir"
      ? new Uint8Array(enc.includes("CBC") ? Number(enc.slice(-3)) / 8 : Number(enc.slice(1, 4)) / 8)
      : alg.startsWith("PBES2")
      ? new TextEncoder().encode("password")
      : new Uint8Array(Number(alg.slice(1, 4)) / 8)
    const ours = await tagged(runToken(encryption.encryptCompact(plaintext, { key: key as any, protectedHeader: { alg, enc } })))
    expect(ours).toBe("UnsupportedAlgorithmError")
    // jose fails too, but with the runtime's raw exception rather than a jose error.
    const theirs = await settle(new jose.CompactEncrypt(plaintext).setProtectedHeader({ alg, enc }).encrypt(key as any))
    expect(theirs.ok).toBe(false)
    expect(theirs.ok === false && theirs.code.startsWith("ERR_")).toBe(false)
  })

  it.runIf(usesAes192(alg, enc))("decrypting a token made elsewhere fails clearly where the runtime lacks 192-bit AES", async ({ skip }) => {
    if (await aes192Supported) return skip("runtime supports 192-bit AES")
    const vector = (vectors as Record<string, { token: string; key: unknown }>)[`${alg}+${enc}`]
    const key = vector.key
    const ours = await tagged(run(encryption.decryptCompact(vector.token, key as any, allow)))
    expect(ours).toBe("UnsupportedAlgorithmError")
    const theirs = await settle(jose.compactDecrypt(vector.token, key as any, allow))
    expect(theirs.ok).toBe(false)
  })

  it("effect encrypts (compact) → jose decrypts", async ({ skip }) => {
    if (usesAes192(alg, enc) && !(await aes192Supported)) return skip("runtime lacks 192-bit AES")
    const material = await keysFor(alg, { enc })
    const jwe = await runToken(encryption.encryptCompact(plaintext, {
      key: material.signOrEncrypt.jwk as any,
      protectedHeader: { alg, enc, kid: "k1" }
    }))
    const out = await jose.compactDecrypt(jwe, material.verifyOrDecrypt.jose as any, allow)
    expect(decode(out.plaintext)).toBe(decode(plaintext))
    expect(out.protectedHeader.kid).toBe("k1")
  })

  it("jose encrypts (compact) → effect decrypts", async ({ skip }) => {
    if (usesAes192(alg, enc) && !(await aes192Supported)) return skip("runtime lacks 192-bit AES")
    const material = await keysFor(alg, { enc })
    const jwe = await new jose.CompactEncrypt(plaintext).setProtectedHeader({ alg, enc }).encrypt(
      material.signOrEncrypt.jose as any
    )
    const out = await run(encryption.decryptCompact(jwe, material.verifyOrDecrypt.jwk as any, allow))
    expect(decode(out.plaintext)).toBe(decode(plaintext))
  })
})

describe("JWE flattened and general serializations", () => {
  it("flattened with AAD and all three header kinds interoperates both ways", async () => {
    const material = await keysFor("ECDH-ES+A256KW")
    const aad = new TextEncoder().encode("additional data")
    const ours = await run(encryption.encryptFlattened(plaintext, {
      key: material.signOrEncrypt.jwk as any,
      protectedHeader: { enc: "A256GCM" },
      sharedUnprotectedHeader: { alg: "ECDH-ES+A256KW" },
      unprotectedHeader: { kid: "r1" },
      additionalAuthenticatedData: aad
    }))
    const theirs = await jose.flattenedDecrypt(ours as any, material.verifyOrDecrypt.jose as any)
    expect(decode(theirs.plaintext)).toBe(decode(plaintext))
    expect(decode(theirs.additionalAuthenticatedData!)).toBe("additional data")

    const joseJwe = await new jose.FlattenedEncrypt(plaintext)
      .setProtectedHeader({ enc: "A256GCM" })
      .setSharedUnprotectedHeader({ alg: "ECDH-ES+A256KW" })
      .setUnprotectedHeader({ kid: "r2" })
      .setAdditionalAuthenticatedData(aad)
      .encrypt(material.signOrEncrypt.jose as any)
    const out = await run(encryption.decryptFlattened(joseJwe as any, material.verifyOrDecrypt.jwk as any))
    expect(decode(out.plaintext)).toBe(decode(plaintext))
    expect(out.unprotectedHeader).toEqual({ kid: "r2" })
  })

  it("general JSON with RSA-OAEP-256, ECDH-ES+A128KW and A256KW recipients interoperates both ways", async () => {
    const [rsa, ecdh, kw] = await Promise.all([keysFor("RSA-OAEP-256"), keysFor("ECDH-ES+A128KW"), keysFor("A256KW")])
    const recipients = [
      [rsa, "RSA-OAEP-256"],
      [ecdh, "ECDH-ES+A128KW"],
      [kw, "A256KW"]
    ] as const
    const ours = await run(encryption.encryptGeneral(plaintext, {
      protectedHeader: { enc: "A128CBC-HS256" },
      recipients: recipients.map(([k, alg]) => ({ key: k.signOrEncrypt.jwk as any, unprotectedHeader: { alg } }))
    }))
    expect(ours.recipients).toHaveLength(3)
    for (const [k] of recipients) {
      const out = await jose.generalDecrypt(ours as any, k.verifyOrDecrypt.jose as any)
      expect(decode(out.plaintext)).toBe(decode(plaintext))
    }

    const encrypt = new jose.GeneralEncrypt(plaintext).setProtectedHeader({ enc: "A128CBC-HS256" })
    for (const [k, alg] of recipients) encrypt.addRecipient(k.signOrEncrypt.jose as any).setUnprotectedHeader({ alg })
    const theirs = await encrypt.encrypt()
    for (const [k] of recipients) {
      const out = await run(encryption.decryptGeneral(theirs as any, k.verifyOrDecrypt.jwk as any))
      expect(decode(out.plaintext)).toBe(decode(plaintext))
    }
  })

  it("ECDH-ES works over every supported curve both ways", async () => {
    for (const crv of ["P-256", "P-384", "P-521", "X25519"]) {
      const material = await keysFor("ECDH-ES", { crv })
      const jwe = await runToken(encryption.encryptCompact(plaintext, {
        key: material.signOrEncrypt.jwk as any,
        protectedHeader: { alg: "ECDH-ES", enc: "A256GCM" }
      }))
      await jose.compactDecrypt(jwe, material.verifyOrDecrypt.jose as any)
      const joseJwe = await new jose.CompactEncrypt(plaintext).setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
        .encrypt(material.signOrEncrypt.jose as any)
      await run(encryption.decryptCompact(joseJwe, material.verifyOrDecrypt.jwk as any))
    }
  })
})
