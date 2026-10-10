/**
 * # Protecting an HttpApi with tokens from an identity provider
 *
 * Three parties, wired together in memory so the example runs anywhere:
 *
 * - **Auth server** (`https://auth.example`): issues ES256 access tokens and
 *   publishes its public keys at `/.well-known/jwks.json`.
 * - **API** (`https://api.example`): an `HttpApi` whose middleware verifies
 *   bearer tokens against the auth server's key set and provides the user.
 * - **Client**: calls the API through `HttpApiClient` with a token.
 *
 * In a real deployment, replace `network` with `FetchHttpClient.layer` and
 * `CryptoLive` with your platform's layer (`NodeCrypto.layer` from
 * `@effect/platform-node`, or the Bun, Deno, or browser equivalent).
 */
import * as Context from "effect/Context"
import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import * as Layer from "effect/Layer"
import * as Schema from "effect/Schema"
import { HttpClient, HttpClientRequest, HttpClientResponse, HttpRouter, HttpServer } from "effect/http"
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

const AUTH = "https://auth.example"
const API = "https://api.example"

// --- API definition, shared by server and client ---------------------------

class User extends Schema.Class<User>("User")({ id: Schema.String, scopes: Schema.Array(Schema.String) }) {}

class Unauthorized extends Schema.TaggedError<Unauthorized>()("Unauthorized", {}, { httpApiStatus: 401 }) {}

class CurrentUser extends Context.Service<CurrentUser, User>()("CurrentUser") {}

class Authorization extends HttpApiMiddleware.Service<Authorization, { provides: CurrentUser }>()("Authorization", {
  error: Unauthorized,
  security: { bearer: HttpApiSecurity.bearer }
}) {}

const Api = HttpApi.make("api").add(
  HttpApiGroup.make("me").add(HttpApiEndpoint.get("whoami", "/me", { success: User })).middleware(Authorization)
)

// --- API server -------------------------------------------------------------

const AccessToken = Schema.Struct({
  ...JsonWebToken.RegisteredClaims.fields,
  sub: Schema.String,
  scope: Schema.String
})

/** Verifies bearer tokens against the auth server's published key set. */
const AuthorizationLive = Layer.effect(
  Authorization,
  Effect.gen(function*() {
    const keys = yield* JsonWebKeySet.makeRemote(`${AUTH}/.well-known/jwks.json`)
    // Fetch the key set at startup rather than on the first request.
    yield* keys.refresh
    const context = yield* Effect.context<HttpClient.HttpClient | Crypto.Crypto>()

    return Authorization.of({
      bearer: (effect, { credential }) =>
        Effect.provideServiceEffect(
          effect,
          CurrentUser,
          JsonWebToken.verify(credential, keys, {
            schema: AccessToken,
            algorithms: ["ES256"],
            issuer: AUTH,
            audience: API
          }).pipe(
            Effect.map(({ payload }) => new User({ id: payload.sub, scopes: payload.scope.split(" ") })),
            Effect.tapError((error) => Effect.logWarning("rejected bearer token", error._tag)),
            Effect.mapError(() => new Unauthorized()),
            Effect.provideContext(context)
          )
        )
    })
  })
)

const MeLive = HttpApiBuilder.group(Api, "me", (handlers) => handlers.handle("whoami", () => Effect.service(CurrentUser)))

const ApiServer = HttpApiBuilder.layer(Api).pipe(
  Layer.provide(MeLive),
  Layer.provide(AuthorizationLive),
  Layer.provide(HttpServer.layerServices)
)

// --- Auth server ------------------------------------------------------------

const makeAuthServer = Effect.gen(function*() {
  const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair("ES256", { extractable: true })
  const kid = yield* JsonWebKey.thumbprint(publicKey)
  const jwks = { keys: [{ ...(yield* JsonWebKey.exportJwk(publicKey)), kid, use: "sig", alg: "ES256" }] }

  const issueToken = (sub: string, scope: string) =>
    JsonWebToken.sign({ sub, scope }, {
      key: privateKey,
      protectedHeader: { alg: "ES256", kid },
      issuer: AUTH,
      audience: API,
      expirationTime: "5 minutes"
    })

  const handler = (request: Request) =>
    new URL(request.url).pathname === "/.well-known/jwks.json"
      ? new Response(JSON.stringify(jwks), { headers: { "cache-control": "max-age=300" } })
      : new Response(null, { status: 404 })

  return { issueToken, handler }
})

// --- In-memory network ------------------------------------------------------

/** An `HttpClient` that delivers requests to in-process handlers by origin. */
const network = (servers: Record<string, (request: Request) => Response | Promise<Response>>) =>
  Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      Effect.gen(function*() {
        const web = new Request(request.url, {
          method: request.method,
          headers: request.headers as Record<string, string>
        })
        const server = servers[new URL(request.url).origin]
        const response = server ? yield* Effect.promise(async () => server(web)) : new Response(null, { status: 502 })
        return HttpClientResponse.fromWeb(request, response)
      })
    )
  )

const CryptoLive = Layer.succeed(
  Crypto.Crypto,
  Crypto.make({
    randomBytes: (size) => globalThis.crypto.getRandomValues(new Uint8Array(size)),
    digest: (algorithm, data) =>
      Effect.map(
        Effect.promise(() => globalThis.crypto.subtle.digest(algorithm, new Uint8Array(data))),
        (buffer) => new Uint8Array(buffer)
      ),
    keys: Crypto.makeKeyOperations(globalThis.crypto.subtle)
  })
)

// --- Putting it together: a client calls the API ------------------------------

export const main = Effect.gen(function*() {
  const auth = yield* makeAuthServer
  // The API reaches the auth server over the network.
  const api = HttpRouter.toWebHandler(ApiServer.pipe(Layer.provide([network({ [AUTH]: auth.handler }), CryptoLive])), {
    disableLogger: true
  })
  yield* Effect.addFinalizer(() => Effect.promise(api.dispose))

  const callWhoami = (authorize: (request: HttpClientRequest.HttpClientRequest) => HttpClientRequest.HttpClientRequest) =>
    Effect.gen(function*() {
      const client = yield* HttpApiClient.make(Api, {
        baseUrl: API,
        transformClient: HttpClient.mapRequest(authorize)
      })
      return yield* client.me.whoami()
    }).pipe(Effect.provide(network({ [API]: (request) => api.handler(request) })))

  const token = yield* auth.issueToken("user-123", "read:me write:me")
  const user = yield* callWhoami(HttpClientRequest.bearerToken(token))
  yield* Effect.log("authenticated as", user.id, user.scopes)

  const anonymous = yield* Effect.flip(callWhoami((request) => request))
  yield* Effect.log("without a token:", anonymous._tag)

  const forged = yield* Effect.flip(callWhoami(HttpClientRequest.bearerToken("e30.e30.AAAA")))
  yield* Effect.log("with a forged token:", forged._tag)

  return { user: { id: user.id, scopes: user.scopes }, anonymous: anonymous._tag, forged: forged._tag }
}).pipe(Effect.scoped, Effect.provide(CryptoLive))

if (import.meta.main) Effect.runPromise(main)
