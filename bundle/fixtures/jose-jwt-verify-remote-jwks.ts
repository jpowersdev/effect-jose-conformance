import { createRemoteJWKSet, jwtVerify } from "jose"
declare const token: string
const keys = createRemoteJWKSet(new URL("https://issuer.example/.well-known/jwks.json"))
jwtVerify(token, keys, { algorithms: ["RS256", "ES256"], issuer: "https://issuer.example" })
