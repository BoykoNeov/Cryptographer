/**
 * View-mode store. Three mutually-exclusive views over the same spec/trace:
 *
 *   - "linear" — today's per-frame view (matrix/bytes, step description,
 *     param editor). Default; matches the pre-Slice-2 behavior.
 *   - "graph"  — read-only 2D aux-flow graph derived from spec + trace
 *     via `core/graph.ts`. The first visible Family-3 milestone.
 *   - "json"   — raw JSON of the active spec. Useful for copy/paste,
 *     future import/export, and inspecting what the spec mutators
 *     actually produce.
 *
 * Persisted in localStorage so the user's pick survives a reload — flipping
 * back to a fresh "linear" every time would lose the editor mode they were
 * working in.
 *
 * Read from anywhere via `useViewMode()`; write via `setViewMode`.
 */

import { createSignal } from "solid-js";

export const ALL_VIEW_MODES = ["linear", "graph", "json"] as const;
export type ViewMode = (typeof ALL_VIEW_MODES)[number];

export const VIEW_MODE_LABELS: Readonly<Record<ViewMode, string>> = {
  linear: "linear",
  graph: "graph",
  json: "JSON",
};

const STORAGE_KEY = "cryptographer.viewMode";

const loadInitial = (): ViewMode => {
  // Same defensive pattern as stores/format.ts — localStorage is absent in
  // vitest's node env and could throw in private mode. Default to "linear".
  try {
    if (typeof localStorage === "undefined") return "linear";
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw && (ALL_VIEW_MODES as readonly string[]).includes(raw)) {
      return raw as ViewMode;
    }
  } catch {
    // Storage access denied; fall through to default.
  }
  return "linear";
};

const [viewMode, setViewModeSignal] = createSignal<ViewMode>(loadInitial());

export const useViewMode = () => viewMode;

export const setViewMode = (mode: ViewMode): void => {
  setViewModeSignal(mode);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, mode);
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

/**
 * Reset back to the default ("linear") and clear localStorage. Tests use
 * this to isolate cases that swap view modes; production code never calls it.
 */
export const __resetViewModeForTests = (): void => {
  setViewModeSignal("linear");
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
