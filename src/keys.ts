import * as jose from "jose"

/**
 * Generates keys for an algorithm with jose and returns them as extractable
 * CryptoKeys plus their JWK forms, so both libraries can use the same key.
 */
export interface KeyMaterial {
  readonly alg: string
  /** Key used to sign / encrypt. */
  readonly signOrEncrypt: { readonly jose: unknown; readonly jwk: jose.JWK | Uint8Array }
  /** Key used to verify / decrypt. */
  readonly verifyOrDecrypt: { readonly jose: unknown; readonly jwk: jose.JWK | Uint8Array }
}

const cbcBits: Record<string, number> = { "A128CBC-HS256": 256, "A192CBC-HS384": 384, "A256CBC-HS512": 512 }
const gcmBits: Record<string, number> = { A128GCM: 128, A192GCM: 192, A256GCM: 256 }

const strip = (jwk: jose.JWK): jose.JWK => {
  const { key_ops: _ops, ext: _ext, ...rest } = jwk as jose.JWK & { key_ops?: unknown; ext?: unknown }
  return rest
}

export const secretFor = (alg: string, enc?: string): Uint8Array => {
  if (alg === "dir") return crypto.getRandomValues(new Uint8Array((cbcBits[enc!] ?? gcmBits[enc!]) / 8))
  if (alg.startsWith("PBES2")) return new TextEncoder().encode("correct horse battery staple")
  const hs = /^HS(\d{3})$/.exec(alg)
  if (hs) return crypto.getRandomValues(new Uint8Array(Number(hs[1]) / 8))
  const kw = /^A(\d{3})(GCM)?KW$/.exec(alg)
  if (kw) return crypto.getRandomValues(new Uint8Array(Number(kw[1]) / 8))
  throw new Error(`no secret for ${alg}`)
}

export const isSymmetric = (alg: string) =>
  alg === "dir" || alg.startsWith("HS") || alg.startsWith("PBES2") || /^A\d{3}(GCM)?KW$/.test(alg)

export const keysFor = async (alg: string, options?: { enc?: string; crv?: string }): Promise<KeyMaterial> => {
  if (isSymmetric(alg)) {
    const secret = secretFor(alg, options?.enc)
    return { alg, signOrEncrypt: { jose: secret, jwk: secret }, verifyOrDecrypt: { jose: secret, jwk: secret } }
  }
  const { privateKey, publicKey } = await jose.generateKeyPair(alg, {
    extractable: true,
    ...(options?.crv ? { crv: options.crv } : {})
  })
  const privateJwk = strip(await jose.exportJWK(privateKey))
  const publicJwk = strip(await jose.exportJWK(publicKey))
  const signing = alg.startsWith("RSA-OAEP") || alg.startsWith("ECDH")
  return signing
    ? {
      alg,
      signOrEncrypt: { jose: publicKey, jwk: publicJwk },
      verifyOrDecrypt: { jose: privateKey, jwk: privateJwk }
    }
    : {
      alg,
      signOrEncrypt: { jose: privateKey, jwk: privateJwk },
      verifyOrDecrypt: { jose: publicKey, jwk: publicJwk }
    }
}
