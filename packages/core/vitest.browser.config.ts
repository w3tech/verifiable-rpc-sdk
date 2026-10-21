import { fileURLToPath } from "node:url";
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

// Resolve workspace packages from `src`, as the root config does, so the browser job needs no build.
export default defineConfig({
  resolve: {
    alias: [
      {
        find: "@w3tech.io/dstack-verify",
        replacement: fileURLToPath(new URL("../dstack-verify/src/index.ts", import.meta.url)),
      },
    ],
  },
  test: {
    include: ["browser/**/*.test.ts"],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
    },
  },
});
