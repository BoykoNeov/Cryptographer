/**
 * URL hatch for the canonical 4-rail Twofish round layout (2026-07-12).
 *
 * **OFF by default** — Twofish rounds render the generic vertical-stack layout
 * (the "original" view) unless `?twofish4rail=1` is present on the URL. The
 * canonical 4-rail cell (two g-columns, PHT, R2/R3 mix rails, recombine) is a
 * newer, denser rendering; keeping it behind a flag lets it be compared
 * side-by-side with the generic stack without deleting either code path. The
 * whole `twofish-shape.ts` / `twofish-layout.ts` machinery stays live — this
 * flag only decides whether `GraphView` consults it.
 *
 * **Why a URL hatch and not a toolbar toggle.** Same reasoning as
 * `offsets-hatch.ts`: a comparison flag that exists to A/B two layouts doesn't
 * need a persistent pixel-costing toolbar control. The URL flag is easy to flip
 * and to share with the next session.
 *
 * **Why lazy read.** `window.location.search` is read fresh per call so jsdom
 * tests can flip the flag mid-test via `replaceState`. Layout reactivity
 * already re-runs whenever a render-triggering signal changes, so one
 * `URLSearchParams` parse per render is negligible.
 */
export const isTwofishCanonicalEnabled = (): boolean => {
  // Client-only app; the SSR/no-window branch stays OFF defensively.
  if (typeof window === "undefined") return false;
  const params = new URLSearchParams(window.location.search);
  // OFF unless explicitly enabled with `?twofish4rail=1`.
  return params.get("twofish4rail") === "1";
};

/**
 * Imperative override for jsdom-style tests that need to flip the flag without
 * mutating `window.location`. When `enabled` is null, falls back to URL parsing.
 * NOT for production callers — production goes through `isTwofishCanonicalEnabled`.
 */
let testOverride: boolean | null = null;

export const __setTwofishCanonicalEnabledForTest = (enabled: boolean | null): void => {
  testOverride = enabled;
};

export const isTwofishCanonicalEnabledForLayout = (): boolean => {
  if (testOverride !== null) return testOverride;
  return isTwofishCanonicalEnabled();
};
