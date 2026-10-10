import * as jose from "jose"
import * as Effect from "effect/Effect"
import * as FetchHttpClient from "effect/http/FetchHttpClient"
import * as TestClock from "effect/testing/TestClock"
import { JsonWebKeySet, JsonWebSignature, JsonWebToken } from "effect/jose"
import { beforeAll, describe, expect, it } from "vitest"
import { jwksEndpoint } from "../src/jwksEndpoint.ts"
import { keysFor, type KeyMaterial } from "../src/keys.ts"
import { settle } from "../src/outcome.ts"
import { anySignatureAlgorithm, keySets, run, signatures, tokens } from "../src/runtime.ts"

const payload = new TextEncoder().encode("payload")

const signed = async (k: KeyMaterial, header: jose.CompactJWSHeaderParameters) =>
  new jose.CompactSign(payload).setProtectedHeader(header).sign(k.signOrEncrypt.jose as any)

describe("local JWKS selection matches jose", () => {
  let es1: KeyMaterial, es2: KeyMaterial, rs: KeyMaterial, ed: KeyMaterial, es384: KeyMaterial
  let jwks: { keys: Array<jose.JWK> }

  beforeAll(async () => {
    ;[es1, es2, rs, ed, es384] = await Promise.all([keysFor("ES256"), keysFor("ES256"), keysFor("RS256"), keysFor("EdDSA"), keysFor("ES384")])
    jwks = {
      keys: [
        { ...(es1.verifyOrDecrypt.jwk as jose.JWK), kid: "es-1", use: "sig" },
        { ...(es2.verifyOrDecrypt.jwk as jose.JWK), kid: "es-2", alg: "ES256" },
        { ...(rs.verifyOrDecrypt.jwk as jose.JWK), kid: "rs" },
        { ...(ed.verifyOrDecrypt.jwk as jose.JWK), kid: "ed" },
        { ...(es384.verifyOrDecrypt.jwk as jose.JWK), kid: "es384", use: "enc" }
      ]
    }
  })

  const scenarios: ReadonlyArray<readonly [string, () => Promise<string>]> = [
    ["kid selects ES256 key", () => signed(es1, { alg: "ES256", kid: "es-1" })],
    ["kid selects second ES256 key", () => signed(es2, { alg: "ES256", kid: "es-2" })],
    ["no kid, multiple ES256 candidates", () => signed(es1, { alg: "ES256" })],
    ["no kid, single RS256 candidate", () => signed(rs, { alg: "RS256" })],
    ["no kid, EdDSA", () => signed(ed, { alg: "EdDSA" })],
    ["unknown kid", () => signed(es1, { alg: "ES256", kid: "missing" })],
    ["kid matches but wrong key signed", () => signed(es2, { alg: "ES256", kid: "es-1" })],
    ["key restricted to use=enc", () => signed(es384, { alg: "ES384", kid: "es384" })],
    ["symmetric alg against a key set", () => new jose.CompactSign(payload).setProtectedHeader({ alg: "HS256" }).sign(new Uint8Array(32))],
    ["PS256 can use the RSA key", async () => {
      const { privateKey } = { privateKey: await jose.importJWK((await keysFor("PS256")).signOrEncrypt.jwk as jose.JWK, "PS256") }
      return new jose.CompactSign(payload).setProtectedHeader({ alg: "PS256", kid: "rs" }).sign(privateKey)
    }]
  ]

  it.each(scenarios)("%s", async (_, makeToken) => {
    const token = await makeToken()
    const joseOutcome = await settle(jose.compactVerify(token, jose.createLocalJWKSet(jwks)))
    const effectOutcome = await settle(run(Effect.flatMap(keySets.makeLocal(jwks as any), (resolver) =>
      signatures.verifyCompact(token, resolver, { algorithms: anySignatureAlgorithm }))))
    expect(effectOutcome).toEqual(joseOutcome)
  })

  it("malformed key sets are rejected", async () => {
    for (const bad of [{}, { keys: "x" }, { keys: [1] }]) {
      const ours = await settle(run(keySets.makeLocal(bad as any)))
      let theirs: Awaited<ReturnType<typeof settle>>
      try {
        jose.createLocalJWKSet(bad as any)
        theirs = { ok: true }
      } catch (e) {
        theirs = { ok: false, code: (e as jose.errors.JOSEError).code }
      }
      expect(ours).toEqual(theirs)
    }
  })

  it("works as the key for tokens.verify", async () => {
    const token = await new jose.SignJWT({ sub: "u" }).setProtectedHeader({ alg: "ES256", kid: "es-1" }).sign(es1.signOrEncrypt.jose as any)
    const result = await run(Effect.flatMap(keySets.makeLocal(jwks as any), (resolver) =>
      tokens.verify(token, resolver, { requireExpiration: false, algorithms: ["ES256"] })))
    expect(result.payload.sub).toBe("u")
  })
})

describe("remote JWKS", () => {
  let a: KeyMaterial, b: KeyMaterial

  beforeAll(async () => {
    ;[a, b] = await Promise.all([keysFor("ES256"), keysFor("ES256")])
  })

  it("fetches lazily, caches, refetches on unknown kid after cooldown, and fails with typed errors", async () => {
    const endpoint = await jwksEndpoint({ keys: [{ ...(a.verifyOrDecrypt.jwk as jose.JWK), kid: "a" }] })
    const tokenA = await signed(a, { alg: "ES256", kid: "a" })
    const tokenB = await signed(b, { alg: "ES256", kid: "b" })
    const requests = Effect.promise(endpoint.count)

    const program = Effect.gen(function*() {
      const resolver = yield* keySets.makeRemote(endpoint.url, {
        allowInsecureHttp: true, // the shared test server is plain HTTP
        cooldownDuration: "30 seconds",
        cacheMaxAge: "10 minutes"
      })
      const counts: Array<number> = []
      counts.push(yield* requests) // lazily: nothing fetched yet
      yield* signatures.verifyCompact(tokenA, resolver, { algorithms: anySignatureAlgorithm })
      yield* signatures.verifyCompact(tokenA, resolver, { algorithms: anySignatureAlgorithm })
      counts.push(yield* requests) // one fetch, then cached
      yield* Effect.promise(() =>
        endpoint.set({
          keys: [
            { ...(a.verifyOrDecrypt.jwk as jose.JWK), kid: "a" },
            { ...(b.verifyOrDecrypt.jwk as jose.JWK), kid: "b" }
          ]
        })
      )
      const cooling = yield* Effect.result(signatures.verifyCompact(tokenB, resolver, { algorithms: anySignatureAlgorithm }))
      counts.push(yield* requests) // within cooldown: no refetch
      yield* TestClock.adjust("31 seconds")
      yield* signatures.verifyCompact(tokenB, resolver, { algorithms: anySignatureAlgorithm })
      counts.push(yield* requests) // after cooldown: refetched once, kid "b" now found
      yield* TestClock.adjust("11 minutes")
      yield* signatures.verifyCompact(tokenA, resolver, { algorithms: anySignatureAlgorithm })
      counts.push(yield* requests) // stale cache: refetched
      return { counts, cooling }
    }).pipe(Effect.provide([FetchHttpClient.layer, TestClock.layer()]))

    const { cooling, counts } = await run(program)
    expect(counts).toEqual([0, 1, 1, 2, 3])
    expect(cooling._tag === "Failure" && cooling.failure._tag).toBe("NoMatchingKeyError")
  })

  it("non-200 responses fail with a typed error", async () => {
    const endpoint = await jwksEndpoint()
    const tokenA = await signed(a, { alg: "ES256", kid: "a" })
    const outcome = await settle(run(Effect.gen(function*() {
      const resolver = yield* keySets.makeRemote(endpoint.failUrl, { allowInsecureHttp: true })
      return yield* signatures.verifyCompact(tokenA, resolver, { algorithms: anySignatureAlgorithm })
    }).pipe(Effect.provide(FetchHttpClient.layer))))
    expect(outcome).toEqual({ ok: false, code: "ERR_JOSE_GENERIC" })
    expect(await settle(jose.compactVerify(tokenA, jose.createRemoteJWKSet(new URL(endpoint.failUrl))))).toEqual(outcome)
  })
})
