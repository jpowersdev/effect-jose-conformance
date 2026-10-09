import * as jose from "jose"
import * as Effect from "effect/Effect"
import * as FetchHttpClient from "effect/http/FetchHttpClient"
import * as KeyValueStore from "effect/persistence/KeyValueStore"
import { JsonWebKeySet, JsonWebSignature } from "effect/jose"
import { describe, expect, it } from "vitest"
import { jwksEndpoint } from "../src/jwksEndpoint.ts"
import { keysFor } from "../src/keys.ts"
import { settle } from "../src/outcome.ts"
import { run } from "../src/runtime.ts"

const payload = new TextEncoder().encode("payload")

describe("embedded JWK verification matches jose's EmbeddedJWK", () => {
  const scenarios: ReadonlyArray<readonly [string, () => Promise<string>]> = [
    ["public key in the protected header", async () => {
      const k = await keysFor("ES256")
      return new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256", jwk: k.verifyOrDecrypt.jwk as jose.JWK })
        .sign(k.signOrEncrypt.jose as any)
    }],
    ["EdDSA key", async () => {
      const k = await keysFor("EdDSA")
      return new jose.CompactSign(payload).setProtectedHeader({ alg: "EdDSA", jwk: k.verifyOrDecrypt.jwk as jose.JWK })
        .sign(k.signOrEncrypt.jose as any)
    }],
    ["no jwk header", async () => {
      const k = await keysFor("ES256")
      return new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256" }).sign(k.signOrEncrypt.jose as any)
    }],
    ["private key embedded", async () => {
      const k = await keysFor("ES256")
      return new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256", jwk: k.signOrEncrypt.jwk as jose.JWK })
        .sign(k.signOrEncrypt.jose as any)
    }],
    ["embedded key did not sign the token", async () => {
      const [a, b] = await Promise.all([keysFor("ES256"), keysFor("ES256")])
      return new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256", jwk: b.verifyOrDecrypt.jwk as jose.JWK })
        .sign(a.signOrEncrypt.jose as any)
    }]
  ]

  it.each(scenarios)("%s", async (_, makeToken) => {
    const token = await makeToken()
    expect(await settle(run(JsonWebSignature.verifyCompact(token, JsonWebSignature.embeddedKey)))).toEqual(
      await settle(jose.compactVerify(token, jose.EmbeddedJWK))
    )
  })
})

describe("several matching keys", () => {
  const setup = async () => {
    const [a, b] = await Promise.all([keysFor("ES256"), keysFor("ES256")])
    const jwks = { keys: [a.verifyOrDecrypt.jwk as jose.JWK, b.verifyOrDecrypt.jwk as jose.JWK] }
    const token = await new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256" }).sign(b.signOrEncrypt.jose as any)
    return { jwks, token }
  }

  it("fails by default, like jose", async () => {
    const { jwks, token } = await setup()
    expect(await settle(run(Effect.flatMap(JsonWebKeySet.makeLocal(jwks as any), (r) => JsonWebSignature.verifyCompact(token, r)))))
      .toEqual(await settle(jose.compactVerify(token, jose.createLocalJWKSet(jwks))))
  })

  it("tryEach gives the same result as looping over jose's candidates by hand", async () => {
    const { jwks, token } = await setup()
    let joseResult: Awaited<ReturnType<typeof jose.compactVerify>> | undefined
    try {
      await jose.compactVerify(token, jose.createLocalJWKSet(jwks))
    } catch (error) {
      for await (const candidate of error as jose.errors.JWKSMultipleMatchingKeys) {
        try {
          joseResult = await jose.compactVerify(token, candidate)
          break
        } catch {
          // try the next candidate
        }
      }
    }
    const ours = await run(Effect.flatMap(
      JsonWebKeySet.makeLocal(jwks as any, { multipleMatches: "tryEach" }),
      (resolver) => JsonWebSignature.verifyCompact(token, resolver)
    ))
    expect(joseResult).toBeDefined()
    expect(ours.payload).toEqual(joseResult!.payload)
    expect(ours.protectedHeader).toEqual(joseResult!.protectedHeader)
  })
})

describe("remote key set storage", () => {
  it("a fresh resolver reuses the stored set, like jose's jwksCache", async () => {
    const k = await keysFor("ES256")
    const jwks = { keys: [{ ...(k.verifyOrDecrypt.jwk as jose.JWK), kid: "k" }] }
    const token = await new jose.CompactSign(payload).setProtectedHeader({ alg: "ES256", kid: "k" }).sign(
      k.signOrEncrypt.jose as any
    )
    const ours = await jwksEndpoint(jwks)
    const coldStart = Effect.gen(function*() {
      const resolver = yield* JsonWebKeySet.makeRemote(ours.url, { storage: "keyValueStore", allowInsecureHttp: true })
      return yield* JsonWebSignature.verifyCompact(token, resolver)
    })
    await run(Effect.gen(function*() {
      yield* coldStart
      yield* coldStart
      yield* coldStart
    }).pipe(Effect.provide([FetchHttpClient.layer, KeyValueStore.layerMemory])))

    const theirs = await jwksEndpoint(jwks)
    const cache: jose.ExportedJWKSCache = {} as any
    for (let i = 0; i < 3; i++) {
      await jose.compactVerify(token, jose.createRemoteJWKSet(new URL(theirs.url), { [jose.jwksCache]: cache }))
    }
    expect(await ours.count()).toBe(1)
    expect(await ours.count()).toBe(await theirs.count())
  })
})
