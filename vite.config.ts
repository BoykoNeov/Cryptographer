import { totalmem } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
/// <reference types="vitest" />
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Pick a fork-pool worker cap based on host RAM.
//
// Why this exists: vitest defaults to one worker per logical CPU, and
// each worker reserves ~1 GB+ of virtual memory for V8 heap regions +
// jsdom + the Vite transform pipeline. On a memory-constrained Windows
// box (16 GB RAM + ~2.4 GB page file → ~18 GB total commit limit, of
// which baseline OS+apps already consume ~12.5 GB), 12 concurrent
// workers blow past the commit headroom and V8's Zone allocator aborts
// with "Zone Allocation failed - process out of memory" at trivial heap
// usage — sometimes single-digit MB, before any user test code runs.
//
// Scaling by total RAM means contributors on roomier boxes (32 GB, 64
// GB, CI runners) get more parallelism automatically. The
// VITEST_MAX_FORKS env var is an escape hatch if the heuristic guesses
// wrong on a given machine.
function pickMaxForks(): number | undefined {
  const override = process.env.VITEST_MAX_FORKS;
  if (override !== undefined && override !== "") {
    const n = Number(override);
    if (Number.isFinite(n) && n > 0) return n;
  }
  const totalGB = totalmem() / 1024 ** 3;
  if (totalGB < 24) return 2; // 16 GB tier — pin to 2, OS commit is tight
  if (totalGB < 48) return 4; // 32 GB tier — comfortable middle ground
  return undefined; // 48 GB+ — let vitest default to one-per-CPU
}
const MAX_FORKS = pickMaxForks();

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
    // Fork-pool concurrency cap. See pickMaxForks() above for the
    // memory-pressure reasoning. When MAX_FORKS is undefined the
    // poolOptions block is omitted entirely so vitest falls back to
    // its default (one worker per logical CPU).
    pool: "forks",
    ...(MAX_FORKS !== undefined && {
      poolOptions: {
        forks: {
          maxForks: MAX_FORKS,
          minForks: 1,
        },
      },
    }),
  },
});
