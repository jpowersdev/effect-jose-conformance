/**
 * Vitest global setup: an HTTP server that serves JSON Web Key Sets to tests
 * in every runtime, including browsers (hence the permissive CORS headers).
 *
 * Each test claims its own endpoint id and controls it over HTTP:
 *
 * - `PUT  /:id/jwks`  sets the key set served at `GET /:id/jwks`
 * - `GET  /:id/count` returns how many times `GET /:id/jwks` was requested
 * - `GET  /:id/fail`  always responds with 500
 * - `GET  /:id/redirect` redirects to `/:id/jwks`
 * - `GET  /:id/big`   serves the key set padded beyond 128 KiB
 */
import { createServer } from "node:http"
import type { TestProject } from "vitest/node"

declare module "vitest" {
  export interface ProvidedContext {
    jwksServerUrl: string
  }
}

export default async function setup(project: TestProject) {
  const bodies = new Map<string, string>()
  const counts = new Map<string, number>()
  const server = createServer((req, res) => {
    res.setHeader("access-control-allow-origin", "*")
    res.setHeader("access-control-allow-methods", "GET, PUT, OPTIONS")
    res.setHeader("access-control-allow-headers", "*")
    if (req.method === "OPTIONS") return void res.writeHead(204).end()
    const [, id, action] = (req.url ?? "").split("/")
    if (action === "fail") return void res.writeHead(500).end()
    if (action === "redirect") return void res.writeHead(302, { location: `/${id}/jwks` }).end()
    if (action === "big") {
      const body = JSON.parse(bodies.get(id) ?? '{"keys":[]}')
      return void res.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({ ...body, padding: "x".repeat(200_000) })
      )
    }
    if (action === "count") {
      return void res.writeHead(200, { "content-type": "application/json" }).end(String(counts.get(id) ?? 0))
    }
    if (action === "jwks" && req.method === "PUT") {
      let body = ""
      req.on("data", (chunk) => (body += chunk))
      req.on("end", () => {
        bodies.set(id, body)
        res.writeHead(204).end()
      })
      return
    }
    if (action === "jwks") {
      counts.set(id, (counts.get(id) ?? 0) + 1)
      return void res.writeHead(200, { "content-type": "application/json" }).end(bodies.get(id) ?? '{"keys":[]}')
    }
    res.writeHead(404).end()
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const { port } = server.address() as { port: number }
  project.provide("jwksServerUrl", `http://127.0.0.1:${port}`)
  return () => new Promise<void>((resolve) => server.close(() => resolve()))
}
