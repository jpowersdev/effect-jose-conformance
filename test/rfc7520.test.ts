/**
 * Conformance tests against RFC 7520, "Examples of Protecting Content Using
 * JSON Object Signing and Encryption (JOSE)".
 *
 * All keys, inputs, and expected outputs are transcribed from
 * https://www.rfc-editor.org/rfc/rfc7520.txt into
 * `test/fixtures/rfc7520/figures.json`, keyed by RFC figure number. Wrapped
 * base64url strings were joined without whitespace, JSON figures were parsed
 * after re-joining wrapped string values, and the "\xNN" byte escapes used in
 * the RFC text (U+2019, U+2013) were decoded to their UTF-8 characters.
 */
import { readFileSync } from "node:fs"
import { JsonWebEncryption, JsonWebKey, JsonWebSignature } from "effect/jose"
import { describe, expect, it } from "vitest"
import { run } from "../src/runtime.ts"

type Json = any

const figures: Record<string, { readonly caption: string; readonly value: Json }> = JSON.parse(
  readFileSync(new URL("./fixtures/rfc7520/figures.json", import.meta.url), "utf8")
)
const fig = (n: number): Json => {
  const figure = figures[String(n)]
  if (!figure) throw new Error(`missing RFC 7520 Figure ${n}`)
  return figure.value
}

const b64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"))
const utf8 = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)
const encodeUtf8 = (s: string): Uint8Array => new TextEncoder().encode(s)

const publicJwk = (jwk: Json): Json => {
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = jwk
  return pub
}

/**
 * Imports a private ephemeral JWK as an extractable key. Passing the private
 * JWK directly as `keyManagementParameters.epk` also works (see the
 * regression tests below); both paths are exercised.
 */
const ephemeralKey = (jwk: Json, alg: string) => run(JsonWebKey.importJwk(jwk, alg, { extractable: true })) as Promise<Json>

/** Resolves with the tagged error a failing effect produced. */
const failure = async (promise: Promise<unknown>): Promise<Json> => {
  try {
    await promise
  } catch (error) {
    return error
  }
  throw new Error("expected the operation to fail")
}

// ---------------------------------------------------------------------------
// Section 3: keys
// ---------------------------------------------------------------------------
const ecPublic = fig(1) // P-521, bilbo.baggins, use "sig"
const ecPrivate = fig(2)
const rsaPublic = fig(3) // RSA 2048, bilbo.baggins, use "sig"
const rsaPrivate = fig(4)
const hmacKey = fig(5) // oct, HS256, use "sig"

// Section 4 payload
const payloadText: string = fig(7)
const payloadB64: string = fig(8)

describe("RFC 7520 fixture sanity", () => {
  it("Figure 8 is the base64url encoding of Figure 7", () => {
    expect(utf8(b64(payloadB64))).toBe(payloadText)
    expect(payloadText).toContain("’")
  })
  it("Figure 72 contains the U+2013 EN DASH", () => {
    expect(fig(72)).toContain("–")
  })
})

// ---------------------------------------------------------------------------
// Section 4: JSON Web Signature examples
// ---------------------------------------------------------------------------
describe("RFC 7520 Section 4.1 RSA v1.5 Signature (RS256)", () => {
  const header = fig(9) // {"alg":"RS256","kid":"bilbo.baggins@hobbiton.example"}
  const compact: string = fig(13)

  it("protected header serializes to Figure 10", () => {
    expect(Buffer.from(JSON.stringify(header)).toString("base64url")).toBe(compact.split(".")[0])
  })
  it("signCompact produces Figure 13 exactly", async () => {
    const jws = await run(JsonWebSignature.signCompact(payloadText, { key: rsaPrivate, protectedHeader: header }))
    expect(jws).toBe(compact)
  })
  it("signFlattened produces Figure 15 exactly", async () => {
    const jws = await run(JsonWebSignature.signFlattened(payloadText, { key: rsaPrivate, protectedHeader: header }))
    expect(jws).toEqual(fig(15))
  })
  it("signGeneral produces Figure 14 exactly", async () => {
    const jws = await run(JsonWebSignature.signGeneral(payloadText, [{ key: rsaPrivate, protectedHeader: header }]))
    expect(jws).toEqual(fig(14))
  })
  it("verifies Figure 13 (compact)", async () => {
    const out = await run(JsonWebSignature.verifyCompact(compact, rsaPublic))
    expect(utf8(out.payload)).toBe(payloadText)
    expect(out.protectedHeader).toEqual(header)
  })
  it("verifies Figure 14 (general) and Figure 15 (flattened)", async () => {
    expect(utf8((await run(JsonWebSignature.verifyGeneral(fig(14), rsaPublic))).payload)).toBe(payloadText)
    expect(utf8((await run(JsonWebSignature.verifyFlattened(fig(15), rsaPublic))).payload)).toBe(payloadText)
  })
})

describe("RFC 7520 Section 4.2 RSA-PSS Signature (PS384)", () => {
  // RSASSA-PSS is randomized: only verify the RFC outputs.
  it("verifies Figure 20 (compact)", async () => {
    const out = await run(JsonWebSignature.verifyCompact(fig(20), rsaPublic))
    expect(utf8(out.payload)).toBe(payloadText)
    expect(out.protectedHeader).toEqual(fig(16))
  })
  it("verifies Figure 21 (general) and Figure 22 (flattened)", async () => {
    expect(utf8((await run(JsonWebSignature.verifyGeneral(fig(21), rsaPublic))).payload)).toBe(payloadText)
    expect(utf8((await run(JsonWebSignature.verifyFlattened(fig(22), rsaPublic))).payload)).toBe(payloadText)
  })
  it("a freshly produced PS384 signature verifies", async () => {
    const jws = await run(JsonWebSignature.signCompact(payloadText, { key: rsaPrivate, protectedHeader: fig(16) }))
    expect(jws.split(".").slice(0, 2).join(".")).toBe((fig(20) as string).split(".").slice(0, 2).join("."))
    expect(utf8((await run(JsonWebSignature.verifyCompact(jws, rsaPublic))).payload)).toBe(payloadText)
  })
})

describe("RFC 7520 Section 4.3 ECDSA Signature (ES512)", () => {
  // ECDSA is randomized: only verify the RFC outputs.
  it("verifies Figure 27 (compact)", async () => {
    const out = await run(JsonWebSignature.verifyCompact(fig(27), ecPublic))
    expect(utf8(out.payload)).toBe(payloadText)
    expect(out.protectedHeader).toEqual(fig(23))
  })
  it("verifies Figure 28 (general) and Figure 29 (flattened)", async () => {
    expect(utf8((await run(JsonWebSignature.verifyGeneral(fig(28), ecPublic))).payload)).toBe(payloadText)
    expect(utf8((await run(JsonWebSignature.verifyFlattened(fig(29), ecPublic))).payload)).toBe(payloadText)
  })
  it("a freshly produced ES512 signature verifies", async () => {
    const jws = await run(JsonWebSignature.signCompact(payloadText, { key: ecPrivate, protectedHeader: fig(23) }))
    expect(utf8((await run(JsonWebSignature.verifyCompact(jws, ecPublic))).payload)).toBe(payloadText)
  })
})

describe("RFC 7520 Section 4.4 HMAC-SHA2 Integrity Protection (HS256)", () => {
  const header = fig(30)
  it("signCompact produces Figure 34 exactly", async () => {
    expect(await run(JsonWebSignature.signCompact(payloadText, { key: hmacKey, protectedHeader: header }))).toBe(fig(34))
  })
  it("signGeneral / signFlattened produce Figures 35 / 36 exactly", async () => {
    expect(await run(JsonWebSignature.signGeneral(payloadText, [{ key: hmacKey, protectedHeader: header }]))).toEqual(
      fig(35)
    )
    expect(await run(JsonWebSignature.signFlattened(payloadText, { key: hmacKey, protectedHeader: header }))).toEqual(
      fig(36)
    )
  })
  it("verifies Figures 34, 35, 36", async () => {
    expect(utf8((await run(JsonWebSignature.verifyCompact(fig(34), hmacKey))).payload)).toBe(payloadText)
    expect(utf8((await run(JsonWebSignature.verifyGeneral(fig(35), hmacKey))).payload)).toBe(payloadText)
    expect(utf8((await run(JsonWebSignature.verifyFlattened(fig(36), hmacKey))).payload)).toBe(payloadText)
  })
})

describe("RFC 7520 Section 4.5 Signature with Detached Content (HS256)", () => {
  const compact: string = fig(41) // header..signature
  it("Figure 41 matches the attached signature with the payload removed", async () => {
    const jws = await run(JsonWebSignature.signCompact(payloadText, { key: hmacKey, protectedHeader: fig(37) }))
    const [h, , s] = jws.split(".")
    expect(`${h}..${s}`).toBe(compact)
  })
  it("verifies Figure 41 with the detached payload re-attached", async () => {
    const [protectedHeader, , signature] = compact.split(".")
    const out = await run(
      JsonWebSignature.verifyFlattened({ protected: protectedHeader, payload: payloadB64, signature }, hmacKey)
    )
    expect(utf8(out.payload)).toBe(payloadText)
  })
  it("verifies Figures 42 (general) and 43 (flattened) with the detached payload re-attached", async () => {
    const general = fig(42)
    const flattened = fig(43)
    expect(general.payload).toBeUndefined()
    expect(flattened.payload).toBeUndefined()
    expect(
      utf8((await run(JsonWebSignature.verifyGeneral({ ...general, payload: payloadB64 }, hmacKey))).payload)
    ).toBe(payloadText)
    expect(
      utf8((await run(JsonWebSignature.verifyFlattened({ ...flattened, payload: payloadB64 }, hmacKey))).payload)
    ).toBe(payloadText)
  })
  it("a detached JWS does not verify without the payload", async () => {
    const error = await failure(run(JsonWebSignature.verifyGeneral(fig(42), hmacKey)))
    expect(error._tag).toBe("SignatureVerificationError")
  })
})

describe("RFC 7520 Section 4.6 Protecting Specific Header Fields (HS256)", () => {
  const options = { key: hmacKey, protectedHeader: fig(44), unprotectedHeader: fig(46) }
  it("signFlattened produces Figure 50 exactly", async () => {
    expect(await run(JsonWebSignature.signFlattened(payloadText, options))).toEqual(fig(50))
  })
  it("signGeneral produces Figure 49 exactly", async () => {
    expect(await run(JsonWebSignature.signGeneral(payloadText, [options]))).toEqual(fig(49))
  })
  it("verifies Figures 49 and 50", async () => {
    const flat = await run(JsonWebSignature.verifyFlattened(fig(50), hmacKey))
    expect(utf8(flat.payload)).toBe(payloadText)
    expect(flat.protectedHeader).toEqual(fig(44))
    expect(flat.unprotectedHeader).toEqual(fig(46))
    expect(utf8((await run(JsonWebSignature.verifyGeneral(fig(49), hmacKey))).payload)).toBe(payloadText)
  })
})

describe("RFC 7520 Section 4.7 Protecting Content Only (HS256)", () => {
  const options = { key: hmacKey, unprotectedHeader: fig(51) }
  it("signFlattened produces Figure 55 exactly", async () => {
    expect(await run(JsonWebSignature.signFlattened(payloadText, options))).toEqual(fig(55))
  })
  it("signGeneral produces Figure 54 exactly", async () => {
    expect(await run(JsonWebSignature.signGeneral(payloadText, [options]))).toEqual(fig(54))
  })
  it("verifies Figures 54 and 55", async () => {
    const flat = await run(JsonWebSignature.verifyFlattened(fig(55), hmacKey))
    expect(utf8(flat.payload)).toBe(payloadText)
    expect(flat.protectedHeader).toBeUndefined()
    expect(flat.unprotectedHeader).toEqual(fig(51))
    expect(utf8((await run(JsonWebSignature.verifyGeneral(fig(54), hmacKey))).payload)).toBe(payloadText)
  })
})

describe("RFC 7520 Section 4.8 Multiple Signatures", () => {
  const general = fig(71)
  it("signGeneral reproduces the deterministic RS256 and HS256 signatures (Figures 61, 70)", async () => {
    const jws = await run(JsonWebSignature.signGeneral(payloadText, [
      { key: rsaPrivate, protectedHeader: fig(56), unprotectedHeader: fig(58) },
      { key: ecPrivate, unprotectedHeader: fig(62) },
      { key: hmacKey, protectedHeader: fig(66) }
    ]))
    expect(jws.payload).toBe(general.payload)
    expect(jws.signatures).toHaveLength(3)
    expect(jws.signatures[0]).toEqual(fig(61))
    expect(jws.signatures[2]).toEqual(fig(70))
    // ES512 is randomized: check the header and that it verifies.
    expect(jws.signatures[1].header).toEqual(fig(62))
    expect(jws.signatures[1].protected).toBeUndefined()
    const out = await run(JsonWebSignature.verifyFlattened({ ...jws.signatures[1], payload: jws.payload }, ecPublic))
    expect(utf8(out.payload)).toBe(payloadText)
  })
  it("Figure 71 signatures match Figures 61, 65, 70", () => {
    expect(general.signatures).toEqual([fig(61), fig(65), fig(70)])
  })
  it("verifies Figure 71 with each of the three keys", async () => {
    for (const key of [rsaPublic, ecPublic, hmacKey]) {
      const out = await run(JsonWebSignature.verifyGeneral(general, key))
      expect(utf8(out.payload)).toBe(payloadText)
    }
  })
  it("verifies each Figure 71 signature individually as flattened JWS", async () => {
    const keys = [rsaPublic, ecPublic, hmacKey]
    for (let i = 0; i < 3; i++) {
      const out = await run(
        JsonWebSignature.verifyFlattened({ ...general.signatures[i], payload: general.payload }, keys[i])
      )
      expect(utf8(out.payload)).toBe(payloadText)
    }
  })
})

// ---------------------------------------------------------------------------
// Section 5: JSON Web Encryption examples
// ---------------------------------------------------------------------------
const plaintext: string = fig(72)

const compactParts = (jwe: string) => {
  const [protectedHeader, encryptedKey, iv, ciphertext, tag] = jwe.split(".")
  return { protectedHeader, encryptedKey, iv, ciphertext, tag }
}

describe("RFC 7520 Section 5.1 Key Encryption Using RSA v1.5 and AES-HMAC-SHA2", () => {
  const key = fig(73)
  // RSA1_5 is intentionally not supported by effect/jose.
  it("decryptCompact of Figure 81 fails with UnsupportedAlgorithmError", async () => {
    const error = await failure(run(JsonWebEncryption.decryptCompact(fig(81), key)))
    expect(error._tag).toBe("UnsupportedAlgorithmError")
  })
  it("decryptFlattened of Figure 83 fails with UnsupportedAlgorithmError", async () => {
    const error = await failure(run(JsonWebEncryption.decryptFlattened(fig(83), key)))
    expect(error._tag).toBe("UnsupportedAlgorithmError")
  })
  it("decryptGeneral of Figure 82 fails", async () => {
    // decryptGeneral skips recipients it cannot process and reports a generic failure.
    const error = await failure(run(JsonWebEncryption.decryptGeneral(fig(82), key)))
    expect(["UnsupportedAlgorithmError", "DecryptionError"]).toContain(error._tag)
  })
})

describe("RFC 7520 Section 5.2 Key Encryption Using RSA-OAEP with AES-GCM", () => {
  // RSA-OAEP is randomized: only decrypt.
  const key = fig(84)
  it("decrypts Figure 92 (compact)", async () => {
    const out = await run(JsonWebEncryption.decryptCompact(fig(92), key))
    expect(utf8(out.plaintext)).toBe(plaintext)
    expect(out.protectedHeader).toEqual(fig(88))
  })
  it("decrypts Figure 93 (general) and Figure 94 (flattened)", async () => {
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(fig(93), key))).plaintext)).toBe(plaintext)
    expect(utf8((await run(JsonWebEncryption.decryptFlattened(fig(94), key))).plaintext)).toBe(plaintext)
  })
  it("a fresh RSA-OAEP encryption with the RFC CEK/IV decrypts and reproduces the content", async () => {
    const jwe = await run(JsonWebEncryption.encryptCompact(plaintext, {
      key: publicJwk(key),
      protectedHeader: fig(88),
      cek: b64(fig(85)),
      iv: b64(fig(86))
    }))
    const rfc = compactParts(fig(92))
    const ours = compactParts(jwe)
    // Header, IV, ciphertext and tag depend only on header/CEK/IV and are deterministic.
    expect(ours.protectedHeader).toBe(rfc.protectedHeader)
    expect(ours.iv).toBe(rfc.iv)
    expect(ours.ciphertext).toBe(rfc.ciphertext)
    expect(ours.tag).toBe(rfc.tag)
    expect(utf8((await run(JsonWebEncryption.decryptCompact(jwe, key))).plaintext)).toBe(plaintext)
  })
})

describe("RFC 7520 Section 5.3 Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2", () => {
  const password = encodeUtf8(fig(96))
  // The plaintext is the Figure 95 JWK Set with all whitespace removed.
  const jwkSet = JSON.stringify(fig(95))
  const options = { keyManagementAlgorithms: ["PBES2-HS512+A256KW"] }
  const kmp = { p2s: b64(fig(99)), p2c: fig(101).p2c as number }

  it("PBES2 is rejected unless explicitly allowed", async () => {
    const error = await failure(run(JsonWebEncryption.decryptCompact(fig(105), password)))
    expect(error._tag).toBe("AlgorithmNotAllowedError")
  })
  it("decrypts Figure 105 (compact)", async () => {
    const out = await run(JsonWebEncryption.decryptCompact(fig(105), password, options))
    expect(utf8(out.plaintext)).toBe(jwkSet)
    expect(out.protectedHeader).toEqual(fig(101))
  })
  it("decrypts Figure 106 (general) and Figure 107 (flattened)", async () => {
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(fig(106), password, options))).plaintext)).toBe(jwkSet)
    expect(utf8((await run(JsonWebEncryption.decryptFlattened(fig(107), password, options))).plaintext)).toBe(jwkSet)
  })
  it("encryptCompact with the RFC p2s/p2c/CEK reproduces the Figure 100 encrypted key and round-trips", async () => {
    const { alg, cty, enc } = fig(101)
    const jwe = await run(JsonWebEncryption.encryptCompact(jwkSet, {
      key: password,
      protectedHeader: { alg, cty, enc },
      cek: b64(fig(97)),
      iv: b64(fig(98)),
      keyManagementParameters: kmp
    }))
    const ours = compactParts(jwe)
    expect(ours.encryptedKey).toBe(fig(100))
    expect(ours.iv).toBe(fig(98))
    // The implementation appends p2c/p2s after the user header members, so
    // the protected header (and therefore the AAD, ciphertext and tag) differ
    // in member order from the RFC's {"alg","p2s","p2c","cty","enc"}.
    expect(JSON.parse(utf8(b64(ours.protectedHeader)))).toEqual(fig(101))
    expect(utf8((await run(JsonWebEncryption.decryptCompact(jwe, password, options))).plaintext)).toBe(jwkSet)
  })
  it("encryptCompact reproduces Figure 105 exactly when the header lists p2s/p2c in RFC order", async () => {
    // p2s/p2c are given in the protected header in the RFC's position; the
    // implementation overwrites them in place with the values it uses.
    const jwe = await run(JsonWebEncryption.encryptCompact(jwkSet, {
      key: password,
      protectedHeader: fig(101),
      cek: b64(fig(97)),
      iv: b64(fig(98)),
      keyManagementParameters: kmp
    }))
    expect(jwe).toBe(fig(105))
  })
})

describe("RFC 7520 Section 5.4 Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM", () => {
  const key = fig(108)
  const epk = fig(111)
  it("decrypts Figure 117 (compact)", async () => {
    const out = await run(JsonWebEncryption.decryptCompact(fig(117), key))
    expect(utf8(out.plaintext)).toBe(plaintext)
    expect(out.protectedHeader).toEqual(fig(113))
  })
  it("decrypts Figure 118 (general) and Figure 119 (flattened)", async () => {
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(fig(118), key))).plaintext)).toBe(plaintext)
    expect(utf8((await run(JsonWebEncryption.decryptFlattened(fig(119), key))).plaintext)).toBe(plaintext)
  })
  it("encryptCompact with the RFC ephemeral key/CEK/IV reproduces the Figure 112 encrypted key and round-trips", async () => {
    const { alg, kid, enc } = fig(113)
    const jwe = await run(JsonWebEncryption.encryptCompact(plaintext, {
      key: publicJwk(key),
      protectedHeader: { alg, kid, enc },
      cek: b64(fig(109)),
      iv: b64(fig(110)),
      keyManagementParameters: { epk: await ephemeralKey(epk, alg) }
    }))
    const ours = compactParts(jwe)
    expect(ours.encryptedKey).toBe(fig(112))
    expect(ours.iv).toBe(fig(110))
    // The protected header is semantically identical to Figure 113, but the
    // implementation serializes "epk" as {x,crv,kty,y} and appends it after
    // the user header, so the header bytes (thus AAD, ciphertext, tag) cannot
    // match the RFC's byte-for-byte. An exact compact match is not asserted.
    expect(JSON.parse(utf8(b64(ours.protectedHeader)))).toEqual(fig(113))
    expect(utf8((await run(JsonWebEncryption.decryptCompact(jwe, key))).plaintext)).toBe(plaintext)
  })
  // Regression: a private JWK `epk` used to be imported non-extractable and
  // then exported to build the "epk" header, which failed.
  it("accepts the Figure 111 private JWK directly as keyManagementParameters.epk", async () => {
    const { alg, kid, enc } = fig(113)
    const jwe = await run(JsonWebEncryption.encryptCompact(plaintext, {
      key: publicJwk(key),
      protectedHeader: { alg, kid, enc },
      cek: b64(fig(109)),
      iv: b64(fig(110)),
      keyManagementParameters: { epk }
    }))
    expect(compactParts(jwe).encryptedKey).toBe(fig(112))
  })
})

describe("RFC 7520 Section 5.5 Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2", () => {
  const key = fig(120)
  const epk = fig(122)
  it("decrypts Figure 128 (compact)", async () => {
    const out = await run(JsonWebEncryption.decryptCompact(fig(128), key))
    expect(utf8(out.plaintext)).toBe(plaintext)
    expect(out.protectedHeader).toEqual(fig(124))
  })
  it("decrypts Figure 129", async () => {
    // RFC 7520's "General JWE JSON Serialization" for ECDH-ES (Figure 129)
    // has no "recipients" member, i.e. it is structurally a flattened JWE.
    const out = await run(JsonWebEncryption.decryptFlattened(fig(129), key))
    expect(utf8(out.plaintext)).toBe(plaintext)
  })
  it("encryptCompact with the RFC ephemeral key/IV round-trips", async () => {
    const { alg, kid, enc } = fig(124)
    const jwe = await run(JsonWebEncryption.encryptCompact(plaintext, {
      key: publicJwk(key),
      protectedHeader: { alg, kid, enc },
      iv: b64(fig(121)),
      keyManagementParameters: { epk: await ephemeralKey(epk, alg) }
    }))
    const ours = compactParts(jwe)
    expect(ours.encryptedKey).toBe("")
    expect(ours.iv).toBe(fig(121))
    // As in 5.4, the "epk" member order differs from Figure 124, so only a
    // semantic header comparison and a round trip are asserted.
    expect(JSON.parse(utf8(b64(ours.protectedHeader)))).toEqual(fig(124))
    expect(utf8((await run(JsonWebEncryption.decryptCompact(jwe, key))).plaintext)).toBe(plaintext)
  })
  // Regression: same as in 5.4 (private JWK epk).
  it("accepts the Figure 122 private JWK directly as keyManagementParameters.epk", async () => {
    const { alg, kid, enc } = fig(124)
    const jwe = await run(JsonWebEncryption.encryptCompact(plaintext, {
      key: publicJwk(key),
      protectedHeader: { alg, kid, enc },
      iv: b64(fig(121)),
      keyManagementParameters: { epk }
    }))
    expect(utf8((await run(JsonWebEncryption.decryptCompact(jwe, key))).plaintext)).toBe(plaintext)
  })
})

describe("RFC 7520 Section 5.6 Direct Encryption Using AES-GCM", () => {
  const key = fig(130)
  it("encryptCompact produces Figure 136 exactly", async () => {
    const jwe = await run(JsonWebEncryption.encryptCompact(plaintext, {
      key,
      protectedHeader: fig(132),
      iv: b64(fig(131))
    }))
    expect(jwe).toBe(fig(136))
  })
  it("encryptFlattened produces Figure 137 exactly", async () => {
    // Figure 137 is labelled "General JWE JSON Serialization" but has no
    // "recipients" member; it is the flattened form.
    const jwe = await run(JsonWebEncryption.encryptFlattened(plaintext, {
      key,
      protectedHeader: fig(132),
      iv: b64(fig(131))
    }))
    expect(jwe).toEqual(fig(137))
  })
  it("decrypts Figure 136 (compact) and Figure 137", async () => {
    const out = await run(JsonWebEncryption.decryptCompact(fig(136), key))
    expect(utf8(out.plaintext)).toBe(plaintext)
    expect(out.protectedHeader).toEqual(fig(132))
    expect(utf8((await run(JsonWebEncryption.decryptFlattened(fig(137), key))).plaintext)).toBe(plaintext)
  })
})

describe("RFC 7520 Section 5.7 Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2", () => {
  const key = fig(138)
  const kmp = { iv: b64(fig(141)) }
  it("decrypts Figure 148 (compact)", async () => {
    const out = await run(JsonWebEncryption.decryptCompact(fig(148), key))
    expect(utf8(out.plaintext)).toBe(plaintext)
    expect(out.protectedHeader).toEqual(fig(144))
  })
  it("decrypts Figure 149 (general) and Figure 150 (flattened)", async () => {
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(fig(149), key))).plaintext)).toBe(plaintext)
    expect(utf8((await run(JsonWebEncryption.decryptFlattened(fig(150), key))).plaintext)).toBe(plaintext)
  })
  it("encryptCompact with the RFC CEK/IV/key-wrap IV reproduces the Figure 142 encrypted key and Figure 143 tag", async () => {
    const { alg, kid, enc } = fig(144)
    const jwe = await run(JsonWebEncryption.encryptCompact(plaintext, {
      key,
      protectedHeader: { alg, kid, enc },
      cek: b64(fig(139)),
      iv: b64(fig(140)),
      keyManagementParameters: kmp
    }))
    const ours = compactParts(jwe)
    expect(ours.encryptedKey).toBe(fig(142))
    const header = JSON.parse(utf8(b64(ours.protectedHeader)))
    expect(header).toEqual(fig(144))
    expect(header.tag).toBe(fig(143))
    expect(utf8((await run(JsonWebEncryption.decryptCompact(jwe, key))).plaintext)).toBe(plaintext)
  })
  it("encryptCompact reproduces Figure 148 exactly when the header lists tag/iv in RFC order", async () => {
    // "tag" and "iv" are given in the protected header in the RFC's position;
    // the implementation overwrites them in place with the values it computes.
    const jwe = await run(JsonWebEncryption.encryptCompact(plaintext, {
      key,
      protectedHeader: fig(144),
      cek: b64(fig(139)),
      iv: b64(fig(140)),
      keyManagementParameters: kmp
    }))
    expect(jwe).toBe(fig(148))
  })
})

describe("RFC 7520 Section 5.8 Key Wrap Using AES-KeyWrap with AES-GCM", () => {
  const key = fig(151)
  const options = { key, protectedHeader: fig(155), cek: b64(fig(152)), iv: b64(fig(153)) }
  it("encryptCompact produces Figure 159 exactly", async () => {
    expect(await run(JsonWebEncryption.encryptCompact(plaintext, options))).toBe(fig(159))
  })
  it("encryptFlattened produces Figure 161 exactly", async () => {
    expect(await run(JsonWebEncryption.encryptFlattened(plaintext, options))).toEqual(fig(161))
  })
  it("encryptGeneral (single recipient, random CEK) round-trips and matches Figure 160's shape", async () => {
    const jwe = await run(JsonWebEncryption.encryptGeneral(plaintext, {
      recipients: [{ key }],
      protectedHeader: fig(155)
    }))
    expect(jwe.protected).toBe(fig(160).protected)
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(jwe, key))).plaintext)).toBe(plaintext)
  })
  it("decrypts Figures 159, 160, 161", async () => {
    expect(utf8((await run(JsonWebEncryption.decryptCompact(fig(159), key))).plaintext)).toBe(plaintext)
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(fig(160), key))).plaintext)).toBe(plaintext)
    expect(utf8((await run(JsonWebEncryption.decryptFlattened(fig(161), key))).plaintext)).toBe(plaintext)
  })
})

describe("RFC 7520 Section 5.9 Compressed Content", () => {
  // "zip" (compression) is intentionally unsupported by effect/jose.
  const key = fig(151)
  it("decryptCompact of Figure 170 fails with UnsupportedAlgorithmError", async () => {
    const error = await failure(run(JsonWebEncryption.decryptCompact(fig(170), key)))
    expect(error._tag).toBe("UnsupportedJweHeaderError")
  })
  it("decryptGeneral / decryptFlattened of Figures 171 / 172 fail", async () => {
    const flat = await failure(run(JsonWebEncryption.decryptFlattened(fig(172), key)))
    expect(flat._tag).toBe("UnsupportedJweHeaderError")
    const general = await failure(run(JsonWebEncryption.decryptGeneral(fig(171), key)))
    expect(["UnsupportedJweHeaderError", "DecryptionError"]).toContain(general._tag)
  })
  it("encrypting with \"zip\" fails with UnsupportedAlgorithmError", async () => {
    const error = await failure(run(JsonWebEncryption.encryptCompact(plaintext, {
      key,
      protectedHeader: fig(166),
      cek: b64(fig(163)),
      iv: b64(fig(164))
    })))
    expect(error._tag).toBe("UnsupportedJweHeaderError")
  })
})

describe("RFC 7520 Section 5.10 Including Additional Authenticated Data", () => {
  const key = fig(151)
  const aad = b64(fig(176))
  it("Figure 176 is the compact JSON of Figure 173", () => {
    expect(JSON.parse(utf8(aad))).toEqual(fig(173))
  })
  it("encryptFlattened produces Figure 183 exactly", async () => {
    const jwe = await run(JsonWebEncryption.encryptFlattened(plaintext, {
      key,
      protectedHeader: fig(178),
      additionalAuthenticatedData: aad,
      cek: b64(fig(174)),
      iv: b64(fig(175))
    }))
    expect(jwe).toEqual(fig(183))
  })
  it("decrypts Figures 182 (general) and 183 (flattened)", async () => {
    const flat = await run(JsonWebEncryption.decryptFlattened(fig(183), key))
    expect(utf8(flat.plaintext)).toBe(plaintext)
    expect(flat.additionalAuthenticatedData).toEqual(aad)
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(fig(182), key))).plaintext)).toBe(plaintext)
  })
})

describe("RFC 7520 Section 5.11 Protecting Specific Header Fields", () => {
  const key = fig(151)
  it("encryptFlattened produces Figure 193 exactly", async () => {
    const jwe = await run(JsonWebEncryption.encryptFlattened(plaintext, {
      key,
      protectedHeader: fig(187),
      sharedUnprotectedHeader: fig(191),
      cek: b64(fig(184)),
      iv: b64(fig(185))
    }))
    expect(jwe).toEqual(fig(193))
  })
  it("decrypts Figures 192 (general) and 193 (flattened)", async () => {
    const flat = await run(JsonWebEncryption.decryptFlattened(fig(193), key))
    expect(utf8(flat.plaintext)).toBe(plaintext)
    expect(flat.protectedHeader).toEqual(fig(187))
    expect(flat.sharedUnprotectedHeader).toEqual(fig(191))
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(fig(192), key))).plaintext)).toBe(plaintext)
  })
})

describe("RFC 7520 Section 5.12 Protecting Content Only", () => {
  const key = fig(151)
  it("encryptFlattened produces Figure 201 exactly", async () => {
    const jwe = await run(JsonWebEncryption.encryptFlattened(plaintext, {
      key,
      sharedUnprotectedHeader: fig(199),
      cek: b64(fig(194)),
      iv: b64(fig(195))
    }))
    expect(jwe).toEqual(fig(201))
  })
  it("decrypts Figures 200 (general) and 201 (flattened)", async () => {
    const flat = await run(JsonWebEncryption.decryptFlattened(fig(201), key))
    expect(utf8(flat.plaintext)).toBe(plaintext)
    expect(flat.protectedHeader).toBeUndefined()
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(fig(200), key))).plaintext)).toBe(plaintext)
  })
})

describe("RFC 7520 Section 5.13 Encrypting to Multiple Recipients", () => {
  const general = fig(221)
  it("Figure 221 recipients match Figures 206, 210, 215", () => {
    expect(general.recipients).toEqual([fig(206), fig(210), fig(215)])
  })
  it("decrypts Figure 221 as recipient #2 (ECDH-ES+A256KW, Figure 108 key)", async () => {
    const out = await run(JsonWebEncryption.decryptGeneral(general, fig(108)))
    expect(utf8(out.plaintext)).toBe(plaintext)
    expect(out.protectedHeader).toEqual(fig(216))
    expect(out.sharedUnprotectedHeader).toEqual(fig(220))
    expect(out.unprotectedHeader).toEqual(fig(209))
  })
  it("decrypts Figure 221 as recipient #3 (A256GCMKW, Figure 138 key)", async () => {
    const out = await run(JsonWebEncryption.decryptGeneral(general, fig(138)))
    expect(utf8(out.plaintext)).toBe(plaintext)
    expect(out.unprotectedHeader).toEqual(fig(214))
  })
  it("recipient #1 (RSA1_5, Figure 73 key) cannot decrypt because RSA1_5 is unsupported", async () => {
    const out = await failure(run(JsonWebEncryption.decryptGeneral(general, fig(73))))
    expect(["UnsupportedAlgorithmError", "DecryptionError"]).toContain(out._tag)
    const { recipients, ...shared } = general
    const flat = await failure(run(JsonWebEncryption.decryptFlattened({ ...shared, ...recipients[0] }, fig(73))))
    expect(flat._tag).toBe("UnsupportedAlgorithmError")
  })
  const encryptToRecipients2And3 = async () => {
    const { alg: alg2, kid: kid2 } = fig(209)
    const { alg: alg3, kid: kid3 } = fig(214)
    return run(JsonWebEncryption.encryptGeneral(plaintext, {
      protectedHeader: fig(216),
      sharedUnprotectedHeader: fig(220),
      recipients: [
        {
          key: publicJwk(fig(108)),
          unprotectedHeader: { alg: alg2, kid: kid2 },
          keyManagementParameters: { epk: await ephemeralKey(fig(207), alg2) }
        },
        { key: fig(138), unprotectedHeader: { alg: alg3, kid: kid3 }, keyManagementParameters: { iv: b64(fig(211)) } }
      ]
    }))
  }
  it("encryptGeneral to recipients #2 and #3 with the RFC ephemeral key / key-wrap IV round-trips", async () => {
    // encryptGeneral generates a random CEK and IV for multiple recipients, so
    // only headers and round trips are asserted.
    const jwe = await encryptToRecipients2And3()
    expect(jwe.unprotected).toEqual(fig(220))
    expect(jwe.recipients[1].header?.iv).toBe(fig(211))
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(jwe, fig(108)))).plaintext)).toBe(plaintext)
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(jwe, fig(138)))).plaintext)).toBe(plaintext)
  })
  // Regression: encryptGeneral used to merge recipient #0's key-management
  // parameters into the shared protected header instead of that recipient's
  // per-recipient header (Figure 221 keeps the protected header as just enc).
  it("keeps recipient #2's epk in its per-recipient header (Figures 210, 217)", async () => {
    const jwe = await encryptToRecipients2And3()
    expect(jwe.protected).toBe(general.protected)
    expect(jwe.recipients[0].header).toEqual(fig(209))
  })
  // Regression: with two ECDH-ES recipients, recipient #1's "epk" used to
  // appear in both the shared and per-recipient headers, so it could not decrypt.
  it("every recipient of a multi-recipient ECDH-ES+AxxxKW JWE can decrypt", async () => {
    const p384 = fig(108)
    const p256 = fig(120)
    const jwe = await run(JsonWebEncryption.encryptGeneral(plaintext, {
      protectedHeader: fig(216),
      recipients: [
        { key: publicJwk(p384), unprotectedHeader: { alg: "ECDH-ES+A256KW" } },
        { key: publicJwk(p256), unprotectedHeader: { alg: "ECDH-ES+A128KW" } }
      ]
    }))
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(jwe, p384))).plaintext)).toBe(plaintext)
    expect(utf8((await run(JsonWebEncryption.decryptGeneral(jwe, p256))).plaintext)).toBe(plaintext)
  })
})
