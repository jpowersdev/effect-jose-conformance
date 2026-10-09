// Generates A192 JWE tokens with jose on Node (which supports 192-bit AES), so
// the browser suite can check decrypting tokens produced elsewhere.
import * as jose from "jose"
import { writeFileSync } from "node:fs"
import { keysFor } from "../src/keys.ts"
const algs = ["dir","RSA-OAEP","RSA-OAEP-256","RSA-OAEP-384","RSA-OAEP-512","ECDH-ES","ECDH-ES+A128KW","ECDH-ES+A192KW","ECDH-ES+A256KW","A128KW","A192KW","A256KW","A128GCMKW","A192GCMKW","A256GCMKW","PBES2-HS256+A128KW","PBES2-HS384+A192KW","PBES2-HS512+A256KW"]
const encs = ["A128GCM","A192GCM","A256GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"]
const out: Record<string, { token: string; key: unknown }> = {}
for (const alg of algs) for (const enc of encs) {
  if (!`${alg}${enc}`.includes("192")) continue
  const k = await keysFor(alg, { enc })
  const token = await new jose.CompactEncrypt(new TextEncoder().encode("hello")).setProtectedHeader({ alg, enc }).encrypt(k.signOrEncrypt.jose as any)
  const dec = k.verifyOrDecrypt.jwk
  out[`${alg}+${enc}`] = { token, key: dec instanceof Uint8Array ? { kty: "oct", k: jose.base64url.encode(dec) } : dec }
}
writeFileSync(new URL("../test/fixtures/aes192-vectors.json", import.meta.url), JSON.stringify(out, null, 1))
console.log(Object.keys(out).length)
