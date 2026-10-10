/**
 * # Protecting an HttpApi with access tokens
 *
 * An API that accepts access tokens issued by an identity provider (Auth0,
 * Okta, Cognito, Keycloak, ...). The `Authorization` middleware verifies the
 * bearer token against the provider's published key set and provides the
 * current user to handlers.
 *
 * The example serves the API on a free port and calls it with the generated
 * client. The identity provider is simulated in memory: everything else is
 * what an application would write.
 */
import * as NodeCrypto from "@effect/platform-node/NodeCrypto"
import * as NodeHttpServer from "@effect/platform-node/NodeHttpServer"
import * as NodeRuntime from "@effect/platform-node/NodeRuntime"
import { Context, Crypto, Effect, Layer, Redacted, Schema } from "effect"
import { HttpClient, HttpClientRequest, HttpClientResponse, HttpRouter } from "effect/http"
import {
  HttpApi,
  HttpApiBuilder,
  HttpApiClient,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiMiddleware,
  HttpApiSecurity
} from "effect/http-api"
import { JsonWebKey, JsonWebKeySet, JsonWebToken } from "effect/jose"

const ISSUER = "https://auth.example.com"
const AUDIENCE = "https://api.example.com"

// -----------------------------------------------------------------------------
// API definition, shared by the server and its clients
// -----------------------------------------------------------------------------

class User extends Schema.Class<User>("User")({
  id: Schema.String,
  scopes: Schema.Array(Schema.String)
}) {}

class Unauthorized extends Schema.TaggedError<Unauthorized>()(
  "Unauthorized",
  { message: Schema.String },
  { httpApiStatus: 401 }
) {}

class CurrentUser extends Context.Service<CurrentUser, User>()("example/CurrentUser") {}

class Authorization extends HttpApiMiddleware.Service<Authorization, {
  provides: CurrentUser
}>()("example/Authorization", {
  requiredForClient: true,
  security: { bearer: HttpApiSecurity.bearer },
  error: Unauthorized
}) {}

class MeGroup extends HttpApiGroup.make("me")
  .add(HttpApiEndpoint.get("whoami", "/me", { success: User }))
  .middleware(Authorization)
{}

class Api extends HttpApi.make("api").add(MeGroup) {}

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

const AccessTokenClaims = Schema.Struct({
  ...JsonWebToken.RegisteredClaims.fields,
  sub: Schema.String,
  scope: Schema.String
})

/** Verifies access tokens against the identity provider's published key set. */
class AccessTokens extends Context.Service<AccessTokens, {
  readonly verify: (token: Redacted.Redacted<string>) => Effect.Effect<User, Unauthorized>
}>()("example/AccessTokens") {
  static readonly layer = Layer.effect(
    AccessTokens,
    Effect.gen(function*() {
      // Captured once, so `verify` has no requirements of its own.
      const crypto = yield* Crypto.Crypto
      const keys = yield* JsonWebKeySet.makeRemote(`${ISSUER}/.well-known/jwks.json`)
      // Fetch the key set while starting up, rather than on the first request.
      yield* keys.refresh

      const verify = Effect.fn("AccessTokens.verify")(
        function*(token: Redacted.Redacted<string>) {
          const { payload } = yield* JsonWebToken.verify(token, keys, {
            schema: AccessTokenClaims,
            algorithms: ["ES256"],
            issuer: ISSUER,
            audience: AUDIENCE
          })
          return new User({ id: payload.sub, scopes: payload.scope.split(" ") })
        },
        Effect.tapError((error) => Effect.logWarning(`Rejected access token: ${error._tag}`)),
        Effect.mapError(() => new Unauthorized({ message: "Invalid access token" })),
        Effect.provideService(Crypto.Crypto, crypto)
      )

      return AccessTokens.of({ verify })
    })
  )
}

const AuthorizationLive = Layer.effect(
  Authorization,
  Effect.gen(function*() {
    const accessTokens = yield* AccessTokens

    return Authorization.of({
      bearer: Effect.fn(function*(httpEffect, { credential }) {
        if (Redacted.value(credential) === "") {
          return yield* new Unauthorized({ message: "Missing access token" })
        }
        const user = yield* accessTokens.verify(credential)
        return yield* Effect.provideService(httpEffect, CurrentUser, user)
      })
    })
  })
)

const MeHandlers = HttpApiBuilder.group(Api, "me", (handlers) => handlers.handle("whoami", () => CurrentUser))

const ApiLive = HttpApiBuilder.layer(Api).pipe(
  Layer.provide(MeHandlers),
  Layer.provide(AuthorizationLive)
)

// In production, serve on a port and reach the identity provider over HTTPS:
//
//   HttpRouter.serve(ApiLive).pipe(
//     Layer.provide(AccessTokens.layer),
//     Layer.provide([
//       NodeHttpServer.layer(createServer, { port: 3000 }),
//       FetchHttpClient.layer,
//       NodeCrypto.layer
//     ])
//   )

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

/** The client half of `Authorization`: sends the bearer token, if there is one. */
const sendToken = (token: Redacted.Redacted<string> | undefined) =>
  HttpApiMiddleware.layerClient(
    Authorization,
    ({ next, request }) => next(token === undefined ? request : HttpClientRequest.bearerToken(request, token))
  )

const whoami = (token?: Redacted.Redacted<string>) =>
  HttpApiClient.make(Api).pipe(
    Effect.flatMap((client) => client.me.whoami()),
    Effect.provide(sendToken(token))
  )

// -----------------------------------------------------------------------------
// A simulated identity provider
// -----------------------------------------------------------------------------

/**
 * Issues access tokens, and answers requests for its key set through
 * `jwksClient`, standing in for the provider's HTTPS endpoint.
 */
class IdentityProvider extends Context.Service<IdentityProvider, {
  readonly issue: (
    claims: { readonly sub: string; readonly scope: string }
  ) => Effect.Effect<Redacted.Redacted<JsonWebToken.Signed>, JsonWebToken.SignError>
  readonly jwksClient: HttpClient.HttpClient
}>()("example/IdentityProvider") {
  static readonly layer = Layer.effect(
    IdentityProvider,
    Effect.gen(function*() {
      // Captured once, so `issue` has no requirements of its own.
      const crypto = yield* Crypto.Crypto
      const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair("ES256")
      const kid = yield* JsonWebKey.thumbprint(publicKey)
      const publicJwk = yield* JsonWebKey.exportJwk(publicKey)
      const jwks = { keys: [{ ...publicJwk, kid, use: "sig", alg: "ES256" }] }

      const issue = Effect.fn("IdentityProvider.issue")(
        function*(claims: { readonly sub: string; readonly scope: string }) {
          return yield* JsonWebToken.sign(claims, {
            key: privateKey,
            protectedHeader: { alg: "ES256", kid },
            issuer: ISSUER,
            audience: AUDIENCE,
            expirationTime: "5 minutes"
          })
        },
        Effect.provideService(Crypto.Crypto, crypto)
      )

      const jwksClient = HttpClient.make((request) =>
        Effect.succeed(HttpClientResponse.fromWeb(
          request,
          request.url === `${ISSUER}/.well-known/jwks.json`
            ? Response.json(jwks, { headers: { "cache-control": "max-age=300" } })
            : new Response(null, { status: 404 })
        ))
      )

      return IdentityProvider.of({ issue, jwksClient })
    })
  )

  /** The `HttpClient` through which the API reaches the provider. */
  static readonly layerHttpClient = Layer.effect(
    HttpClient.HttpClient,
    Effect.map(IdentityProvider, (identityProvider) => identityProvider.jwksClient)
  )
}

// -----------------------------------------------------------------------------
// Run it
// -----------------------------------------------------------------------------

/** Serves the API on a free port, with an `HttpClient` pointed at it. */
const ExampleLive = HttpRouter.serve(ApiLive, { disableLogger: true, disableListenLog: true }).pipe(
  Layer.provide(AccessTokens.layer.pipe(Layer.provide(IdentityProvider.layerHttpClient))),
  Layer.provideMerge(NodeHttpServer.layerTest),
  Layer.provideMerge(IdentityProvider.layer),
  Layer.provide(NodeCrypto.layer)
)

export const main = Effect.gen(function*() {
  const identityProvider = yield* IdentityProvider
  const token = yield* identityProvider.issue({ sub: "user-123", scope: "read:me write:me" })

  const user = yield* whoami(token)
  yield* Effect.log(`Signed in as ${user.id} (${user.scopes.join(", ")})`)

  yield* whoami().pipe(
    Effect.catchTag("Unauthorized", (error) => Effect.log(`Without a token: ${error.message}`))
  )

  yield* whoami(Redacted.make("not.a.token")).pipe(
    Effect.catchTag("Unauthorized", (error) => Effect.log(`With an invalid token: ${error.message}`))
  )
}).pipe(Effect.provide(ExampleLive))

if (import.meta.main) NodeRuntime.runMain(main)
