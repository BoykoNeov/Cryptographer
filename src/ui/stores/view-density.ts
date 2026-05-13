/**
 * View-density store. Scales the graph view's node + gap sizes between three
 * preset densities so the user can either pack more of a wide pipeline into
 * the viewport (compact) or give themselves more breathing room for a
 * walkthrough / projector view (spacious).
 *
 * Why this is its own store (not part of `LayoutSpec`):
 *
 *   `LayoutSpec` is the saved-document sidecar — it travels with the file
 *   and survives reload via the same Save/Load path that carries pinned
 *   positions and collapsed-group state (Slice 6 of the 2D editor plan).
 *   Density is a VIEWER preference, not a document fact: the same shared
 *   `.cipher.json` should render at whatever density the reader prefers,
 *   not whatever density the author happened to be using. Keeping it
 *   here also preserves the Slice 5 byte-stability property: a spec
 *   saved with `includeSession=off` produces identical bytes regardless
 *   of whether the user has flipped density during the session.
 *
 * Persisted in localStorage so the user's pick survives a reload. Mirrors
 * the same defensive pattern as `view-mode.ts` and `format.ts` — quota /
 * private-mode / disabled-cookies failures all fall back to the default.
 *
 * The numeric scale factors live alongside the enum so they're a single
 * source of truth: `GraphView.tsx` imports `DENSITY_SCALE` and multiplies
 * the canonical 1.0× constants by it. Picked symmetric around 1.0 (0.75 /
 * 1.0 / 1.25) so "normal" stays byte-for-byte identical to the layout
 * that shipped pre-density — no visual regression for the default user.
 *
 * Caveat: scaling the leaf rectangle alone isn't enough to fit AES-128's
 * full pipeline into a typical viewport (~2000px at normal → ~1500px at
 * compact, still wider than common ~1200px viewports). This is the FIRST
 * of several readability knobs in the plan's graph-readability sequence;
 * collapse-to-consolidate + fan-out replication land later, and
 * dagre/elkjs orthogonal routing is the escalation if the hand-tuned
 * knobs still can't close the gap.
 */

import { createSignal } from "solid-js";

export const ALL_VIEW_DENSITIES = ["compact", "normal", "spacious"] as const;
export type ViewDensity = (typeof ALL_VIEW_DENSITIES)[number];

export const VIEW_DENSITY_LABELS: Readonly<Record<ViewDensity, string>> = {
  compact: "compact",
  normal: "normal",
  spacious: "spacious",
};

/**
 * Scale factor applied to the size-and-gap layout constants in GraphView.
 * "normal" is exactly 1.0 so the default rendering is byte-identical to
 * the pre-density layout; "compact" / "spacious" are symmetric around it.
 */
export const DENSITY_SCALE: Readonly<Record<ViewDensity, number>> = {
  compact: 0.75,
  normal: 1.0,
  spacious: 1.25,
};

const STORAGE_KEY = "cryptographer.viewDensity";

const loadInitial = (): ViewDensity => {
  // Defensive — localStorage is absent in vitest's node env and can throw
  // in private browsing mode. Fall back to "normal" so first-run users
  // see the canonical layout.
  try {
    if (typeof localStorage === "undefined") return "normal";
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw && (ALL_VIEW_DENSITIES as readonly string[]).includes(raw)) {
      return raw as ViewDensity;
    }
  } catch {
    // Storage access denied; fall through to default.
  }
  return "normal";
};

const [viewDensity, setViewDensitySignal] = createSignal<ViewDensity>(loadInitial());

export const useViewDensity = () => viewDensity;

export const setViewDensity = (density: ViewDensity): void => {
  setViewDensitySignal(density);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, density);
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

/**
 * Reset back to the default ("normal") and clear localStorage. Tests use
 * this to isolate cases that swap density; production code never calls it.
 */
export const __resetViewDensityForTests = (): void => {
  setViewDensitySignal("normal");
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
