/** Confirms each browser instance really is the engine it claims to be. */
import { server } from "vitest/browser"
import { describe, expect, it } from "vitest"

describe("runtime", () => {
  it("runs in the expected browser engine", () => {
    const ua = navigator.userAgent
    const engine = ua.includes("Firefox/") ? "firefox" : ua.includes("Chrome/") ? "chromium" : ua.includes("AppleWebKit/") ? "webkit" : ua
    expect(engine).toBe(server.browser)
  })
})
