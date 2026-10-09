import { inject } from "vitest"

/** A key set endpoint on the shared test server, controlled by one test. */
export interface JwksEndpoint {
  /** URL serving the key set. */
  readonly url: string
  /** URL that always responds with 500. */
  readonly failUrl: string
  /** URL that redirects to `url`. */
  readonly redirectUrl: string
  /** URL serving the key set padded beyond 128 KiB. */
  readonly bigUrl: string
  /** Replaces the served key set. */
  readonly set: (jwks: unknown) => Promise<void>
  /** Number of times the key set has been requested. */
  readonly count: () => Promise<number>
}

export const jwksEndpoint = async (jwks: unknown = { keys: [] }): Promise<JwksEndpoint> => {
  const base = `${inject("jwksServerUrl")}/${crypto.randomUUID()}`
  const endpoint: JwksEndpoint = {
    url: `${base}/jwks`,
    failUrl: `${base}/fail`,
    redirectUrl: `${base}/redirect`,
    bigUrl: `${base}/big`,
    set: async (body) => {
      await fetch(`${base}/jwks`, { method: "PUT", body: JSON.stringify(body) })
    },
    count: async () => Number(await (await fetch(`${base}/count`)).text())
  }
  await endpoint.set(jwks)
  return endpoint
}
