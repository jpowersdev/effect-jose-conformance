import { SignJWT } from "jose"
new SignJWT({ sub: "u" }).setProtectedHeader({ alg: "HS256" }).setExpirationTime("1h").sign(new Uint8Array(32))
