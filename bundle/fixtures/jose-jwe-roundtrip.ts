import { CompactEncrypt, compactDecrypt } from "jose"
const secret = new Uint8Array(32)
new CompactEncrypt(new TextEncoder().encode("x")).setProtectedHeader({ alg: "dir", enc: "A256GCM" }).encrypt(secret)
  .then((jwe) => compactDecrypt(jwe, secret))
