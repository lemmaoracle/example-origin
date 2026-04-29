import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@lemmaoracle/sdk": resolve(
        __dirname,
        "../../node_modules/@lemmaoracle/sdk/dist/index.js",
      ),
    },
  },
});
