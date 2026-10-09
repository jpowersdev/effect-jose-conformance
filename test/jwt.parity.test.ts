import * as jose from "jose"
import * as Effect from "effect/Effect"
import * as Schema from "effect/Schema"
import * as TestClock from "effect/testing/TestClock"
import { JsonWebToken } from "effect/jose"
import { describe, expect, it } from "vitest"
import { keysFor } from "../src/keys.ts"
import { settle } from "../src/outcome.ts"
import { run } from "../src/runtime.ts"

const NOW = 1_700_000_000 // seconds
const currentDate = new Date(NOW * 1000)
const secret = new TextEncoder().encode("a-string-secret-at-least-256-bits-long")

const signWithJose = (payload: jose.JWTPayload, header: jose.JWTHeaderParameters = { alg: "HS256" }) =>
  new jose.SignJWT(payload).setProtectedHeader(header).sign(secret)

interface Scenario {
  readonly name: string
  readonly payload: Record<string, unknown>
  readonly header?: jose.JWTHeaderParameters
  /** Options expressed once; translated to each library's conventions. */
  readonly options?: {
    readonly issuer?: string | Array<string>
    readonly subject?: string
    readonly audience?: string | Array<string>
    readonly typ?: string
    readonly requiredClaims?: Array<string>
    readonly clockToleranceSeconds?: number
    readonly maxTokenAgeSeconds?: number
  }
}

const scenarios: ReadonlyArray<Scenario> = [
  { name: "no claims", payload: {} },
  { name: "valid exp", payload: { exp: NOW + 60 } },
  { name: "expired", payload: { exp: NOW - 1 } },
  { name: "exp equal to now is expired", payload: { exp: NOW } },
  { name: "expired within tolerance", payload: { exp: NOW - 5 }, options: { clockToleranceSeconds: 10 } },
  { name: "expired beyond tolerance", payload: { exp: NOW - 50 }, options: { clockToleranceSeconds: 10 } },
  { name: "nbf in the future", payload: { nbf: NOW + 60 } },
  { name: "nbf within tolerance", payload: { nbf: NOW + 5 }, options: { clockToleranceSeconds: 10 } },
  { name: "nbf now", payload: { nbf: NOW } },
  { name: "exp not a number", payload: { exp: "soon" } },
  { name: "nbf not a number", payload: { nbf: null } },
  { name: "iat not a number", payload: { iat: "x" } },
  { name: "issuer match", payload: { iss: "a" }, options: { issuer: "a" } },
  { name: "issuer in list", payload: { iss: "b" }, options: { issuer: ["a", "b"] } },
  { name: "issuer mismatch", payload: { iss: "c" }, options: { issuer: ["a", "b"] } },
  { name: "issuer missing", payload: {}, options: { issuer: "a" } },
  { name: "subject match", payload: { sub: "u" }, options: { subject: "u" } },
  { name: "subject mismatch", payload: { sub: "v" }, options: { subject: "u" } },
  { name: "audience string match", payload: { aud: "x" }, options: { audience: "x" } },
  { name: "audience array intersects", payload: { aud: ["y", "z"] }, options: { audience: ["x", "z"] } },
  { name: "audience no intersection", payload: { aud: ["y"] }, options: { audience: ["x"] } },
  { name: "audience missing", payload: {}, options: { audience: "x" } },
  { name: "audience wrong type", payload: { aud: 5 }, options: { audience: "x" } },
  { name: "required claim present", payload: { jti: "1" }, options: { requiredClaims: ["jti"] } },
  { name: "required claim missing", payload: {}, options: { requiredClaims: ["jti"] } },
  { name: "typ match with prefix normalization", payload: {}, header: { alg: "HS256", typ: "at+jwt" }, options: { typ: "application/at+jwt" } },
  { name: "typ mismatch", payload: {}, header: { alg: "HS256", typ: "JWT" }, options: { typ: "at+jwt" } },
  { name: "typ missing", payload: {}, options: { typ: "JWT" } },
  { name: "maxTokenAge ok", payload: { iat: NOW - 30 }, options: { maxTokenAgeSeconds: 60 } },
  { name: "maxTokenAge exceeded", payload: { iat: NOW - 120 }, options: { maxTokenAgeSeconds: 60 } },
  { name: "maxTokenAge iat in future", payload: { iat: NOW + 120 }, options: { maxTokenAgeSeconds: 60 } },
  { name: "maxTokenAge iat missing", payload: {}, options: { maxTokenAgeSeconds: 60 } },
  { name: "multiple failures report the same first failure", payload: { iss: "c", exp: NOW - 100 }, options: { issuer: "a" } }
]

describe("JWT claim validation parity with jose", () => {
  it.each(scenarios)("$name", async ({ header, options = {}, payload }) => {
    const token = await signWithJose(payload as jose.JWTPayload, header)
    const joseOutcome = await settle(jose.jwtVerify(token, secret, {
      currentDate,
      ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
      ...(options.subject !== undefined ? { subject: options.subject } : {}),
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
      ...(options.typ !== undefined ? { typ: options.typ } : {}),
      ...(options.requiredClaims !== undefined ? { requiredClaims: options.requiredClaims } : {}),
      ...(options.clockToleranceSeconds !== undefined ? { clockTolerance: options.clockToleranceSeconds } : {}),
      ...(options.maxTokenAgeSeconds !== undefined ? { maxTokenAge: options.maxTokenAgeSeconds } : {})
    }))
    const effectOutcome = await settle(run(JsonWebToken.verify(token, secret, {
      currentDate,
      ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
      ...(options.subject !== undefined ? { subject: options.subject } : {}),
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
      ...(options.typ !== undefined ? { typ: options.typ } : {}),
      ...(options.requiredClaims !== undefined ? { requiredClaims: options.requiredClaims } : {}),
      ...(options.clockToleranceSeconds !== undefined ? { clockTolerance: `${options.clockToleranceSeconds} seconds` as const } : {}),
      ...(options.maxTokenAgeSeconds !== undefined ? { maxTokenAge: `${options.maxTokenAgeSeconds} seconds` as const } : {})
    })))
    expect(effectOutcome).toEqual(joseOutcome)
  })

  it("reports the same failing claim and check as jose", async () => {
    for (const { options = {}, payload } of scenarios) {
      const token = await signWithJose(payload as jose.JWTPayload)
      let joseClaim: unknown
      try {
        await jose.jwtVerify(token, secret, { currentDate, ...(options.issuer ? { issuer: options.issuer } : {}) })
      } catch (e) {
        joseClaim = (e as jose.errors.JWTClaimValidationFailed).claim
      }
      let effectClaim: unknown
      try {
        await run(JsonWebToken.verify(token, secret, { currentDate, ...(options.issuer ? { issuer: options.issuer } : {}) }))
      } catch (e) {
        effectClaim = (e as { claim?: unknown }).claim
      }
      expect(effectClaim).toEqual(joseClaim)
    }
  })
})

describe("JWT issuance interop", () => {
  for (const alg of ["HS256", "RS256", "PS256", "ES256", "EdDSA"] as const) {
    it(`effect issues (${alg}) → jose verifies with identical claims`, async () => {
      const keys = await keysFor(alg)
      const token = await run(
        TestClock.setTime(NOW * 1000).pipe(Effect.andThen(JsonWebToken.sign({ role: "admin", nested: { a: [1, 2] } }, {
          key: keys.signOrEncrypt.jwk as any,
          protectedHeader: { alg, typ: "JWT" },
          issuer: "urn:iss",
          subject: "user-1",
          audience: ["a", "b"],
          jwtId: "id-1",
          issuedAt: true,
          notBefore: "0 seconds",
          expirationTime: "2 hours"
        })), Effect.provide(TestClock.layer()))
      )
      const { payload } = await jose.jwtVerify(token, keys.verifyOrDecrypt.jose as any, {
        issuer: "urn:iss",
        audience: "b",
        subject: "user-1",
        currentDate
      })
      expect(payload).toMatchObject({ role: "admin", nested: { a: [1, 2] }, jti: "id-1", iss: "urn:iss" })
    })
  }

  it("relative times are computed from the Effect Clock", async () => {
    const program = Effect.gen(function*() {
      yield* TestClock.setTime(NOW * 1000)
      return yield* JsonWebToken.sign({}, {
        key: secret,
        protectedHeader: { alg: "HS256" },
        issuedAt: true,
        expirationTime: "1 hour",
        notBefore: "-5 minutes"
      })
    }).pipe(Effect.provide(TestClock.layer()))
    const token = await run(program)
    const claims = jose.decodeJwt(token)
    expect(claims).toEqual({ iat: NOW, exp: NOW + 3600, nbf: NOW - 300 })
  })

  it("verification uses the Effect Clock when currentDate is omitted", async () => {
    const token = await signWithJose({ exp: NOW + 10 })
    const at = (seconds: number) =>
      settle(run(Effect.gen(function*() {
        yield* TestClock.setTime(seconds * 1000)
        return yield* JsonWebToken.verify(token, secret)
      }).pipe(Effect.provide(TestClock.layer()))))
    expect(await at(NOW)).toEqual({ ok: true })
    expect(await at(NOW + 10)).toEqual({ ok: false, code: "ERR_JWT_EXPIRED" })
  })

  it("decodes claims with a Schema", async () => {
    const token = await signWithJose({ sub: "u1", role: "admin" })
    const Claims = Schema.Struct({ ...JsonWebToken.RegisteredClaims.fields, role: Schema.Literals(["admin", "user"]) })
    const { payload } = await run(JsonWebToken.verify(token, secret, { schema: Claims, algorithms: ["HS256"] }))
    expect(payload.role).toBe("admin")
    const bad = await signWithJose({ role: "root" })
    const outcome = await settle(run(JsonWebToken.verify(bad, secret, { schema: Claims })))
    expect(outcome).toEqual({ ok: false, code: "ERR_JWT_CLAIM_VALIDATION_FAILED" })
  })
})

describe("encrypted JWT interop", () => {
  it("effect encrypts → jose decrypts, and back", async () => {
    const keys = await keysFor("ECDH-ES+A256KW")
    const token = await run(JsonWebToken.encrypt({ role: "admin" }, {
      key: keys.signOrEncrypt.jwk as any,
      protectedHeader: { alg: "ECDH-ES+A256KW", enc: "A256GCM" },
      issuer: "urn:iss",
      replicateIssuerAsHeader: true,
      expirationTime: "1 hour"
    }))
    const theirs = await jose.jwtDecrypt(token, keys.verifyOrDecrypt.jose as any, { issuer: "urn:iss" })
    expect(theirs.payload.role).toBe("admin")
    expect(theirs.protectedHeader.iss).toBe("urn:iss")

    const joseToken = await new jose.EncryptJWT({ role: "user" }).setProtectedHeader({
      alg: "ECDH-ES+A256KW",
      enc: "A256GCM"
    }).setIssuer("urn:iss").replicateIssuerAsHeader().encrypt(keys.signOrEncrypt.jose as any)
    const ours = await run(JsonWebToken.decrypt(joseToken, keys.verifyOrDecrypt.jwk as any, { issuer: "urn:iss" }))
    expect(ours.payload.role).toBe("user")
  })
})
