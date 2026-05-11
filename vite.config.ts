import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
/// <reference types="vitest" />
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [solid()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
    // Resolve Solid's browser conditions so the JSX runtime uses the
    // DOM-aware build during tests (and prod, which already does this).
    // Without this vite-plugin-solid resolves Solid's server build in
    // vitest and the first `createSignal` call throws "Client-only API
    // called on the server side."
    conditions: ["development", "browser"],
  },
  test: {
    globals: true,
    // Default env is node (fast, no DOM); UI component tests opt into
    // jsdom per-file via a `// @vitest-environment jsdom` directive at
    // the top of the file.
    environment: "node",
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx", "src/**/*.test.ts", "src/**/*.test.tsx"],
    server: {
      deps: {
        // Inline solid-js so its module-resolution conditions are
        // controlled by our config above, not by vitest's deps cache.
        inline: [/solid-js/],
      },
    },
  },
});
