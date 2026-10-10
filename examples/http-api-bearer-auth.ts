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
import { Context, Effect, Layer, Redacted, Schema } from "effect"
import { FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse, HttpRouter } from "effect/http"
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

class CurrentUser extends Context.Service<
  CurrentUser,
  User
>()("example/CurrentUser") {}

class Authorization extends HttpApiMiddleware.Service<
  Authorization,
  { provides: CurrentUser }
>()("example/Authorization", {
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
class AccessTokens extends Context.Service<
  AccessTokens,
  {
    readonly verify: (token: Redacted.Redacted<string>) => Effect.Effect<User, Unauthorized>
  }
>()("example/AccessTokens") {
  /** The service, with the JOSE services and `HttpClient` left to the caller. */
  static readonly layerNoDeps = Layer.effect(
    AccessTokens,
    Effect.gen(function*() {
      const jwt = yield* JsonWebToken.JsonWebToken
      const keySets = yield* JsonWebKeySet.JsonWebKeySet
      const keySet = yield* keySets.makeRemote(`${ISSUER}/.well-known/jwks.json`)
      // Fetch the key set while starting up, rather than on the first request.
      yield* keySet.refresh

      const verify = Effect.fn("AccessTokens.verify")(
        function*(token: Redacted.Redacted<string>) {
          const { payload } = yield* jwt.verify(token, keySet, {
            schema: AccessTokenClaims,
            algorithms: ["ES256"],
            issuer: ISSUER,
            audience: AUDIENCE
          })
          return new User({ id: payload.sub, scopes: payload.scope.split(" ") })
        },
        Effect.tapError((error) => Effect.logWarning(`Rejected access token: ${error._tag}`)),
        Effect.mapError(() => new Unauthorized({ message: "Invalid access token" }))
      )

      return AccessTokens.of({ verify })
    })
  )

  /** The service, reaching the identity provider over HTTPS. */
  static readonly layer = AccessTokens.layerNoDeps.pipe(
    Layer.provide([
      Layer.mergeAll(JsonWebToken.layer, JsonWebKeySet.layer).pipe(Layer.provide(NodeCrypto.layer)),
      FetchHttpClient.layer
    ])
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

// In production, serve on a port:
//
//   HttpRouter.serve(ApiLive).pipe(
//     Layer.provide(AccessTokens.layer),
//     Layer.provide(NodeHttpServer.layer(createServer, { port: 3000 }))
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
class IdentityProvider extends Context.Service<
  IdentityProvider,
  {
    readonly issue: (
      claims: { readonly sub: string; readonly scope: string }
    ) => Effect.Effect<Redacted.Redacted<JsonWebToken.Signed>, JsonWebToken.SignError>
    readonly jwksClient: HttpClient.HttpClient
  }
>()("example/IdentityProvider") {
  static readonly layer = Layer.effect(
    IdentityProvider,
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jwt = yield* JsonWebToken.JsonWebToken
      const { privateKey, publicKey } = yield* keys.generateKeyPair("ES256")
      const kid = yield* keys.thumbprint(publicKey)
      const publicJwk = yield* keys.exportJwk(publicKey)
      const jwks = { keys: [{ ...publicJwk, kid, use: "sig", alg: "ES256" }] }

      const issue = (claims: { readonly sub: string; readonly scope: string }) =>
        jwt.sign(claims, {
          key: privateKey,
          protectedHeader: { alg: "ES256", kid },
          issuer: ISSUER,
          audience: AUDIENCE,
          expirationTime: "5 minutes"
        })

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
  Layer.provide(AccessTokens.layerNoDeps.pipe(Layer.provide(IdentityProvider.layerHttpClient))),
  Layer.provideMerge(NodeHttpServer.layerTest),
  Layer.provideMerge(IdentityProvider.layer),
  Layer.provide(
    Layer.mergeAll(JsonWebKey.layer, JsonWebKeySet.layer, JsonWebToken.layer).pipe(Layer.provide(NodeCrypto.layer))
  )
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
