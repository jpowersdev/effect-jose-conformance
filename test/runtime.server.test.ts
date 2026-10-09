/**
 * Confirms the suite is running in the runtime it claims to: Vitest's workers
 * inherit the executable that started Vitest, so running Vitest with Deno or
 * Bun runs every test there.
 */
import { describe, expect, inject, it } from "vitest"

declare module "vitest" {
  export interface ProvidedContext {
    expectedRuntime: string
  }
}

const detect = (): string => {
  if ("Deno" in globalThis) return "deno"
  if ("Bun" in globalThis) return "bun"
  return "node"
}

describe("runtime", () => {
  it("runs in the expected runtime", () => {
    const expected = inject("expectedRuntime")
    const [name, major] = expected.split("@")
    expect(detect()).toBe(name)
    if (major !== undefined && name === "node") expect(process.versions.node.split(".")[0]).toBe(major)
  })
})
