/**
 * # Protecting an HttpApi with bearer tokens
 *
 * An `HttpApiMiddleware` reads the bearer token (already `Redacted`), verifies
 * it as a JWT, and provides the authenticated user to handlers. Invalid tokens
 * become a 401.
 *
 * The token verifier is its own service, so the middleware does not care
 * whether keys come from a shared secret, a local key set, or an identity
 * provider (see 03-identity-provider-tokens.ts).
 */
import * as Context from "effect/Context"
import * as Effect from "effect/Effect"
import * as Layer from "effect/Layer"
import * as Redacted from "effect/Redacted"
import * as Schema from "effect/Schema"
import { HttpRouter, HttpServer } from "effect/http"
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup, HttpApiMiddleware, HttpApiSecurity } from "effect/http-api"
import { JsonWebKey, JsonWebKeySet, JsonWebToken } from "effect/jose"
import { CryptoLive } from "./CryptoLive.ts"

// --- API definition -------------------------------------------------------

class User extends Schema.Class<User>("User")({ id: Schema.String, scopes: Schema.Array(Schema.String) }) {}

class Unauthorized extends Schema.TaggedError<Unauthorized>()("Unauthorized", {}, { httpApiStatus: 401 }) {}

class CurrentUser extends Context.Service<CurrentUser, User>()("CurrentUser") {}

class Authorization extends HttpApiMiddleware.Service<Authorization, { provides: CurrentUser }>()("Authorization", {
  error: Unauthorized,
  security: { bearer: HttpApiSecurity.bearer }
}) {}

const Api = HttpApi.make("api").add(
  HttpApiGroup.make("me").add(
    HttpApiEndpoint.get("whoami", "/me", { success: User })
  ).middleware(Authorization)
)

// --- Token verification ---------------------------------------------------

const AccessClaims = Schema.Struct({
  ...JsonWebToken.RegisteredClaims.fields,
  sub: Schema.String,
  scope: Schema.String
})

/** Verifies access tokens. Swap the implementation to change where keys come from. */
class TokenVerifier extends Context.Service<TokenVerifier, {
  readonly verify: (token: Redacted.Redacted<string>) => Effect.Effect<typeof AccessClaims.Type, Unauthorized>
}>()("TokenVerifier") {}

/** A verifier backed by a key set (here built in memory; see example 03 for a remote one). */
const tokenVerifierFrom = (keys: JsonWebKeySet.Resolver) =>
  Layer.effect(
    TokenVerifier,
    Effect.gen(function*() {
      const context = yield* Effect.context<never>()
      return TokenVerifier.of({
        verify: (token) =>
          JsonWebToken.verify(token, keys, {
            schema: AccessClaims,
            algorithms: ["ES256"],
            issuer: "https://auth.example",
            audience: "https://api.example"
          }).pipe(
            Effect.map(({ payload }) => payload),
            // Log the reason, but give clients only a 401.
            Effect.tapError((error) => Effect.logWarning("rejected token", error._tag)),
            Effect.mapError(() => new Unauthorized()),
            Effect.provide(CryptoLive),
            Effect.provideContext(context)
          )
      })
    })
  )

// --- Implementation -------------------------------------------------------

const AuthorizationLive = Layer.effect(
  Authorization,
  Effect.gen(function*() {
    const verifier = yield* TokenVerifier
    return Authorization.of({
      bearer: (effect, { credential }) =>
        Effect.provideServiceEffect(
          effect,
          CurrentUser,
          Effect.map(verifier.verify(credential), (claims) => new User({ id: claims.sub, scopes: claims.scope.split(" ") }))
        )
    })
  })
)

const MeLive = HttpApiBuilder.group(Api, "me", (handlers) => handlers.handle("whoami", () => Effect.service(CurrentUser)))

export const makeApp = (keys: JsonWebKeySet.Resolver) =>
  HttpApiBuilder.layer(Api).pipe(
    Layer.provide(MeLive),
    Layer.provide(AuthorizationLive),
    Layer.provide(tokenVerifierFrom(keys)),
    Layer.provide(HttpServer.layerServices)
  )

// --- Demo: an issuer signs a token, the API checks it ---------------------

export const main = Effect.gen(function*() {
  const signer = yield* JsonWebKey.generateKeyPair("ES256", { extractable: true })
  const jwk = { ...(yield* JsonWebKey.exportJwk(signer.publicKey)), kid: "2026-10" }
  const keys = yield* JsonWebKeySet.makeLocal({ keys: [jwk] })

  const token = yield* JsonWebToken.sign({ sub: "user-123", scope: "read:me" }, {
    key: signer.privateKey,
    protectedHeader: { alg: "ES256", kid: "2026-10" },
    issuer: "https://auth.example",
    audience: "https://api.example",
    expirationTime: "5 minutes"
  })

  const { dispose, handler } = HttpRouter.toWebHandler(makeApp(keys), { disableLogger: true })
  const request = (authorization?: string) =>
    Effect.promise(() =>
      handler(new Request("http://localhost/me", authorization ? { headers: { authorization } } : {}))
    )

  const ok = yield* request(`Bearer ${Redacted.value(token)}`)
  const okBody = yield* Effect.promise(() => ok.json())
  const missing = yield* request()
  const forged = yield* request(`Bearer ${Redacted.value(token).slice(0, -4)}AAAA`)
  yield* Effect.promise(dispose)

  console.log("valid token:", ok.status, okBody)
  console.log("no token:", missing.status)
  console.log("forged token:", forged.status)
  return { ok: ok.status, okBody, missing: missing.status, forged: forged.status }
}).pipe(Effect.provide(CryptoLive))


if (import.meta.main) Effect.runPromise(main)
