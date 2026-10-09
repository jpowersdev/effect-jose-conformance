import { playwright } from "@vitest/browser-playwright"
import { defineConfig } from "vitest/config"

/**
 * Two projects run the same conformance suite:
 *
 * - `server`: Node.js, Deno, or Bun, depending on which executable runs Vitest
 *   (see flake.nix). `EXPECTED_RUNTIME` names the runtime so
 *   `test/runtime.server.test.ts` can confirm the tests really ran there.
 * - `browser`: Chromium, Firefox, and WebKit through Playwright, using the
 *   browsers from nixpkgs when `PLAYWRIGHT_BROWSERS_PATH` is set.
 */
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "server",
          include: ["test/**/*.test.ts"],
          exclude: ["test/**/*.browser.test.ts"],
          globalSetup: ["src/jwksServer.ts"],
          provide: { expectedRuntime: process.env.EXPECTED_RUNTIME ?? "node" }
        }
      },
      {
        test: {
          name: "browser",
          include: ["test/**/*.test.ts"],
          exclude: ["test/**/*.server.test.ts"],
          globalSetup: ["src/jwksServer.ts"],
          testTimeout: 30_000,
          browser: {
            enabled: true,
            headless: true,
            provider: playwright(),
            screenshotFailures: false,
            instances: [{ browser: "chromium" }, { browser: "firefox" }, { browser: "webkit" }]
          }
        }
      }
    ]
  }
})
