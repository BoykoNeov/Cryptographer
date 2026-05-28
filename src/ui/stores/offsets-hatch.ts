/**
 * URL hatch for the offset-based root-level layout experiment
 * (2026-05-28). Activated via `?offsets=1` on any URL pointing at this
 * worktree's dev build.
 *
 * **Why a URL hatch and not a toolbar toggle.** Per the prior
 * `?no-bundle=1` pattern that was used during the gradual obstacle-aware
 * routing slice, viewer prefs that exist for short-lived A/B comparison
 * during development don't need a persistent toolbar surface. The URL
 * flag is easy to flip, easy to share with the next dev session, and
 * costs zero pixels in the UI when the experiment doesn't pan out.
 *
 * **Why lazy read.** `window.location.search` is read fresh per call so
 * jsdom tests can flip the flag mid-test via `replaceState`. The function
 * is short and uncached — no signal/store needed because layout reactivity
 * already re-runs `layoutRoot` whenever a render-triggering signal
 * changes (spec edit, byte format, density, etc.); reading the URL each
 * time `layoutRoot` runs adds one `URLSearchParams` parse per render,
 * negligible.
 */
export const isOffsetsEnabled = (): boolean => {
  if (typeof window === "undefined") return false;
  const params = new URLSearchParams(window.location.search);
  return params.get("offsets") === "1";
};

/**
 * Imperative override for jsdom-style tests that need to flip the flag
 * without mutating `window.location`. Returns a cleanup function. When
 * `enabled` is null, falls back to URL parsing.
 *
 * **NOT exported for production callers** — only tests should depend on
 * the override behavior. Production goes through `isOffsetsEnabled` which
 * reads `window.location.search` directly.
 */
let testOverride: boolean | null = null;

export const __setOffsetsEnabledForTest = (enabled: boolean | null): void => {
  testOverride = enabled;
};

export const isOffsetsEnabledForLayout = (): boolean => {
  if (testOverride !== null) return testOverride;
  return isOffsetsEnabled();
};
