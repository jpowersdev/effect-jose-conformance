/**
 * # Verifying tokens from an identity provider
 *
 * Access tokens issued by Auth0, Okta, Cognito, Entra ID, Keycloak, and so on
 * are verified against the provider's published key set (its `jwks_uri`).
 *
 * - `JsonWebKeySet.makeRemote` fetches the set over HTTPS, caches it (honoring
 *   `Cache-Control`), and refetches when a token names an unknown `kid`, so
 *   key rotation at the provider needs no action.
 * - `refresh` warms the cache when the service starts, so the first request
 *   does not wait for the fetch.
 * - The verifier is a layer, built once and shared by the whole application.
 */
import * as Context from "effect/Context"
import type * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import * as Layer from "effect/Layer"
import * as Redacted from "effect/Redacted"
import * as Schema from "effect/Schema"
import { FetchHttpClient, HttpClient, HttpClientResponse } from "effect/http"
import { JsonWebKey, JsonWebKeySet, JsonWebToken } from "effect/jose"
import { CryptoLive } from "./CryptoLive.ts"

const issuer = "https://tenant.auth.example/"
const audience = "https://api.example"

const AccessToken = Schema.Struct({
  ...JsonWebToken.RegisteredClaims.fields,
  sub: Schema.String,
  scope: Schema.optionalKey(Schema.String)
})

export class AccessTokens extends Context.Service<AccessTokens, {
  readonly verify: (
    token: string
  ) => Effect.Effect<typeof AccessToken.Type, JsonWebToken.VerifyError | JsonWebKeySet.RemoteSelectError>
}>()("AccessTokens") {}

/** Builds the verifier and warms its key cache. Requires `HttpClient` and `Crypto`. */
export const AccessTokensLive = Layer.effect(
  AccessTokens,
  Effect.gen(function*() {
    const keys = yield* JsonWebKeySet.makeRemote(`${issuer}.well-known/jwks.json`, {
      cacheMaxAge: "1 hour",
      cooldownDuration: "30 seconds"
    })
    // Fetch once at startup. Failing here surfaces a misconfigured issuer early.
    yield* keys.refresh
    const context = yield* Effect.context<HttpClient.HttpClient | Crypto.Crypto>()
    return AccessTokens.of({
      verify: (token) =>
        JsonWebToken.verify(token, keys, {
          schema: AccessToken,
          algorithms: ["RS256", "ES256"],
          issuer,
          audience,
          clockTolerance: "30 seconds"
        }).pipe(Effect.map(({ payload }) => payload), Effect.provideContext(context))
    })
  })
)

/** In production: provide `FetchHttpClient.layer` (or your platform's client) and your platform's `Crypto`. */
export const ProductionLayer = AccessTokensLive.pipe(Layer.provide([FetchHttpClient.layer, CryptoLive]))

// --- Demo: stand in for the provider with an in-memory HTTP client --------

export const main = Effect.gen(function*() {
  const provider = yield* JsonWebKey.generateKeyPair("RS256", { extractable: true })
  const jwk = { ...(yield* JsonWebKey.exportJwk(provider.publicKey)), kid: "key-1", use: "sig", alg: "RS256" }
  let fetches = 0
  const FakeProvider = Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      Effect.sync(() => {
        fetches++
        return HttpClientResponse.fromWeb(
          request,
          new Response(JSON.stringify({ keys: [jwk] }), { headers: { "cache-control": "max-age=600" } })
        )
      })
    )
  )

  const token = yield* JsonWebToken.sign({ sub: "auth0|123", scope: "read:orders" }, {
    key: provider.privateKey,
    protectedHeader: { alg: "RS256", kid: "key-1" },
    issuer,
    audience,
    expirationTime: "1 hour"
  })

  // Tokens arrive as plain strings from requests.
  const incoming = Redacted.value(token)

  const claims = yield* Effect.gen(function*() {
    const tokens = yield* AccessTokens
    return yield* tokens.verify(incoming)
  }).pipe(Effect.provide(AccessTokensLive.pipe(Layer.provide([FakeProvider, CryptoLive]))))

  console.log("verified:", claims.sub, claims.scope, `(key set fetched ${fetches} time)`)
  return { sub: claims.sub, fetches }
}).pipe(Effect.provide(CryptoLive))

if (import.meta.main) Effect.runPromise(main)
