import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@aasp/scope-engine": fileURLToPath(
        new URL("./services/scope-engine/src/index.ts", import.meta.url),
      ),
      "@aasp/crawler": fileURLToPath(new URL("./services/crawler/src/index.ts", import.meta.url)),
      "@aasp/api-discovery": fileURLToPath(
        new URL("./services/api-discovery/src/index.ts", import.meta.url),
      ),
      "@aasp/technology-fingerprinter": fileURLToPath(
        new URL("./services/technology-fingerprinter/src/index.ts", import.meta.url),
      ),
      "@aasp/scanner-integrations": fileURLToPath(
        new URL("./services/scanner-integrations/src/index.ts", import.meta.url),
      ),
      "@aasp/scanner-http": fileURLToPath(
        new URL("./services/scanner-http/src/index.ts", import.meta.url),
      ),
      "@aasp/scanner-headers": fileURLToPath(
        new URL("./services/scanner-headers/src/index.ts", import.meta.url),
      ),
      "@aasp/scanner-cookies": fileURLToPath(
        new URL("./services/scanner-cookies/src/index.ts", import.meta.url),
      ),
      "@aasp/scanner-auth-surface": fileURLToPath(
        new URL("./services/scanner-auth-surface/src/index.ts", import.meta.url),
      ),
      "@aasp/scanner-misconfiguration": fileURLToPath(
        new URL("./services/scanner-misconfiguration/src/index.ts", import.meta.url),
      ),
      "@aasp/scanner-cors": fileURLToPath(
        new URL("./services/scanner-cors/src/index.ts", import.meta.url),
      ),
      "@aasp/finding-engine": fileURLToPath(
        new URL("./services/finding-engine/src/index.ts", import.meta.url),
      ),
      "@aasp/correlation-engine": fileURLToPath(
        new URL("./services/correlation-engine/src/index.ts", import.meta.url),
      ),
      "@aasp/ai-engine": fileURLToPath(
        new URL("./services/ai-engine/src/index.ts", import.meta.url),
      ),
      "@aasp/report-engine": fileURLToPath(
        new URL("./services/report-engine/src/index.ts", import.meta.url),
      ),
      "@aasp/schemas": fileURLToPath(new URL("./packages/schemas/src/index.ts", import.meta.url)),
      "@aasp/security-core": fileURLToPath(
        new URL("./packages/security-core/src/index.ts", import.meta.url),
      ),
    },
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts", "apps/**/test/**/*.test.ts"],
    coverage: {
      reporter: ["text", "json-summary"],
    },
  },
});
