import { jwtVerify } from "jose"
declare const token: string
jwtVerify(token, new Uint8Array(32), { algorithms: ["HS256"] })
