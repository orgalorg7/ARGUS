import { defineConfig } from "vitest/config";
import base from "./vitest.config.js";
export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: ["tests/database/**/*.test.ts"],
    exclude: ["node_modules/**"],
    fileParallelism: false,
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
