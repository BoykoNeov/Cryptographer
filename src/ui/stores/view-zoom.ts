/**
 * View-zoom store. Per-spec zoom level for the graph view, so a wide canvas
 * (AES-128 ECB spans ~1800px at normal density and 10 rounds visible) can be
 * scaled down for structure-overview or up for label reading.
 *
 * Slice 3 of the graph-narrative-and-zoom plan
 * (`docs/plans/graph-narrative-and-zoom.md`).
 *
 * Why this is its own store (NOT a field on `LayoutSpec`):
 *
 *   The plan originally suggested layering `viewZoom?: number` onto
 *   `LayoutSpec`. That contradicts the explicit reasoning in
 *   `view-density.ts` for the analogous density preference:
 *
 *     "Density is a VIEWER preference, not a document fact: the same shared
 *      .cipher.json should render at whatever density the reader prefers,
 *      not whatever density the author happened to be using. Keeping it
 *      here also preserves the Slice 5 byte-stability property: a spec
 *      saved with `includeSession=off` produces identical bytes regardless
 *      of whether the user has flipped density during the session."
 *
 *   Zoom is the same kind of preference. Putting it on `LayoutSpec` would
 *   leak the author's zoom into shared `#doc=...` URLs and force a second
 *   round of byte-stability gating in `hasUserLayout()` and the load
 *   boundary. So zoom lives here, alongside density, and is per-`spec.id`
 *   so swapping cipher (AES-128 ↔ Serpent) reloads the zoom that matched
 *   that spec.
 *
 * Persisted in localStorage as one JSON blob `{ [specId]: number }`. Same
 * defensive pattern as `view-density.ts` and `layout.ts` — quota / private-
 * mode / disabled-cookies failures all fall back to the default.
 *
 * Range + step:
 *   - [0.5, 2.0] is wide enough to read AES-256's 14-round body label-by-
 *     label at 2.0× and see the whole pipeline structure at 0.5×.
 *   - Button step is 0.1; the wheel handler in `GraphView.tsx` uses a finer
 *     0.05 step for smoother control.
 *
 * The zoom is applied in `GraphView.tsx` by scaling the SVG's rendered
 * `width`/`height` while keeping `viewBox` at the logical canvas size.
 * Pinned coordinates in `layout.ts` live in viewBox-space, so zoom does NOT
 * call `rescaleAllPositions` — that's density's job, not zoom's.
 */

import { createSignal } from "solid-js";

const STORAGE_KEY = "cryptographer.viewZoom";

/** Hard clamp. Anything outside this range produces poor legibility either way. */
export const VIEW_ZOOM_MIN = 0.5;
export const VIEW_ZOOM_MAX = 2.0;

/** Button-press step (the wheel handler in GraphView uses a finer step). */
export const VIEW_ZOOM_BUTTON_STEP = 0.1;

/** Default. Identical rendering to the pre-Slice-3 layout. */
export const VIEW_ZOOM_DEFAULT = 1.0;

/** Per-spec zoom map: spec.id → zoom factor in [VIEW_ZOOM_MIN, VIEW_ZOOM_MAX]. */
export type ViewZoomMap = { readonly [specId: string]: number };

/** Clamp + sanitize a zoom value. NaN / non-finite → default. */
export const clampZoom = (z: number): number => {
  if (!Number.isFinite(z)) return VIEW_ZOOM_DEFAULT;
  if (z < VIEW_ZOOM_MIN) return VIEW_ZOOM_MIN;
  if (z > VIEW_ZOOM_MAX) return VIEW_ZOOM_MAX;
  return z;
};

/**
 * Hydrate from localStorage. Defensive against missing storage, corrupted
 * JSON, wrong shape, and out-of-range numbers. On any failure the user gets
 * an empty map and zoom returns to default.
 */
const loadInitial = (): ViewZoomMap => {
  try {
    if (typeof localStorage === "undefined") return {};
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: { [specId: string]: number } = {};
    for (const [specId, value] of Object.entries(parsed)) {
      if (typeof value !== "number") continue;
      const clamped = clampZoom(value);
      // Don't bother storing the default — keeps the map minimal.
      if (clamped !== VIEW_ZOOM_DEFAULT) out[specId] = clamped;
    }
    return out;
  } catch {
    return {};
  }
};

const [zoomMap, setZoomMapSignal] = createSignal<ViewZoomMap>(loadInitial());

/**
 * Reactive read of one spec's zoom. Returns `VIEW_ZOOM_DEFAULT` when no
 * entry exists. Use this from JSX so the SVG dimensions react to changes.
 */
export const useViewZoom = (specId: () => string) => () => zoomMap()[specId()] ?? VIEW_ZOOM_DEFAULT;

/** Non-reactive snapshot read for code paths that don't need reactivity. */
export const getViewZoom = (specId: string): number => zoomMap()[specId] ?? VIEW_ZOOM_DEFAULT;

/**
 * Persist best-effort. Failure here doesn't break the session — the
 * in-memory signal is the source of truth for the current tab.
 */
const persist = (map: ViewZoomMap): void => {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
    }
  } catch {
    // Quota / private-mode / disabled cookies. Ignore.
  }
};

/**
 * Set the zoom factor for one spec. Clamps to the supported range. When the
 * resulting zoom equals the default (1.0), the entry is dropped from the
 * map so the persisted blob stays minimal and "no entry === default" is the
 * single invariant readers depend on.
 *
 * Returns the clamped value that was actually applied — handy for tests
 * and for any caller that wants to display the post-clamp number.
 */
export const setViewZoom = (specId: string, zoom: number): number => {
  const clamped = clampZoom(zoom);
  const current = zoomMap();
  const map = { ...current };
  if (clamped === VIEW_ZOOM_DEFAULT) {
    delete (map as { [specId: string]: number })[specId];
  } else {
    map[specId] = clamped;
  }
  setZoomMapSignal(map);
  persist(map);
  return clamped;
};

/**
 * Step the zoom up or down by `VIEW_ZOOM_BUTTON_STEP`. Used by the [+] / [-]
 * toolbar buttons. Rounds to one decimal so repeated stepping doesn't
 * accumulate floating-point drift (`1.0 - 0.1 - 0.1 - ... !== n × 0.1`
 * without rounding).
 */
export const stepViewZoom = (specId: string, direction: 1 | -1): number => {
  const current = getViewZoom(specId);
  const next = Math.round((current + direction * VIEW_ZOOM_BUTTON_STEP) * 100) / 100;
  return setViewZoom(specId, next);
};

/** Reset to default. Drops the entry so localStorage stays minimal. */
export const resetViewZoom = (specId: string): void => {
  setViewZoom(specId, VIEW_ZOOM_DEFAULT);
};

/** Hard reset for tests. Production code never calls this. */
export const __resetViewZoomForTests = (): void => {
  setZoomMapSignal({});
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
