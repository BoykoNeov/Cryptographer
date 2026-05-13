/**
 * Playwright config for the real-browser smoke tests.
 *
 * Scope: the smoke tests verify wiring that jsdom can't realistically check
 * — actual pointer-event drag in a layout engine, native localStorage
 * persistence across a real page reload, file-download / file-upload
 * round-trip through the browser's `<a download>` + file input plumbing.
 * They do NOT duplicate the unit / component tests in `tests/`; vitest is
 * still the load-bearing gate via `npm run check`.
 *
 * Run with `npm run smoke` (headless) or `npm run smoke:headed` (visible
 * Chromium window — useful while iterating on a new spec). The smoke tests
 * are NOT part of `npm run check`: cross-browser launches add seconds to
 * every commit, and the unit gate is what the pre-commit hook protects.
 */

import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  // Failing tests should produce an actionable trace + screenshot but not
  // hang the CI when the dev server doesn't boot.
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://localhost:5173",
    // Capture traces only when a test fails — saves disk space for the
    // common green-run case.
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  // Only chromium for now — the wiring we're checking (pointer events,
  // localStorage, file download) is browser-engine-portable, and running
  // three engines per commit is overkill for a single dev's smoke gate.
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // Boot Vite for the duration of the test run. `reuseExistingServer` lets
  // a developer's already-running `npm run dev` serve the tests instead
  // (no port collision; faster local iteration).
  webServer: {
    command: "npm run dev",
    url: "http://localhost:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
