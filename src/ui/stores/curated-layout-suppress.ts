/**
 * Session-only "suppress the curated default layout" flag, per built-in
 * `spec.id` (graph-legibility plan, Part B — `docs/plans/toasty-zooming-harp.md`).
 *
 * ## Why this exists
 * Part B ships each built-in with a curated default layout that
 * `GraphView.effectiveLayout()` falls back to when the user hasn't dragged
 * anything. "Reset to automatic" must be able to say "ignore the curated
 * default and show raw auto-layout" — but we cannot represent "explicitly
 * empty" in localStorage without a sentinel that breaks spec-only-save
 * byte-stability. So the suppression is a **session-only signal**: a
 * `Set<specId>` that reloading the page clears, bringing the curated default
 * back. This matches every other viewer-local pref (zoom, density, colour /
 * stroke toggles — none survive reload). Persisting "automatic" across reloads
 * is an explicit v1 non-goal (it would reintroduce the sentinel we avoid).
 *
 * The flag is moot once a user layout exists — `effectiveLayout()` returns the
 * user layout regardless — so "reset to automatic" clears the user layout AND
 * sets this flag; "reset to default" clears the user layout AND clears it.
 */

import { createSignal } from "solid-js";

/**
 * Per-spec suppression set. A spec id present here means "skip the curated
 * default for this spec until reset again". Session-only; never persisted.
 */
const [suppressed, setSuppressed] = createSignal<ReadonlySet<string>>(new Set<string>());

/** Reactive read: is the curated default currently suppressed for this spec? */
export const isCuratedLayoutSuppressed = (specId: string): boolean => suppressed().has(specId);

/** Suppress the curated default for `specId` ("reset to automatic"). */
export const suppressCuratedLayout = (specId: string): void => {
  const next = new Set(suppressed());
  next.add(specId);
  setSuppressed(next);
};

/** Un-suppress the curated default for `specId` ("reset to default"). */
export const unsuppressCuratedLayout = (specId: string): void => {
  const cur = suppressed();
  if (!cur.has(specId)) return;
  const next = new Set(cur);
  next.delete(specId);
  setSuppressed(next);
};

/** Test-only reset of the suppression set. */
export const __resetCuratedLayoutSuppressForTests = (): void => {
  setSuppressed(new Set<string>());
};
