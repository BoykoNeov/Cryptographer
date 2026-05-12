/**
 * Layout store. Holds the per-spec graph layout — container positions the
 * user has dragged + the set of containers they've collapsed. One entry per
 * `spec.id` so swapping ciphers (AES-128 ↔ AES-256 ↔ Speck …) reloads the
 * arrangement that matched that spec, not a one-size-fits-all canvas.
 *
 * Slice 6 of the 2D editor plan. The data shape is `LayoutSpec` from
 * `core/document.ts` (already locked by Slice 3's schema), reused verbatim
 * so save/load round-trip is the identity transform.
 *
 * Why "container-only drag" for Slice 6:
 *
 *   The user's pedagogical use case is rearranging WHOLE ROUNDS, not
 *   individual SubBytes/ShiftRows cells. Shipping leaf-level drag now would
 *   force a "leaf escapes parent container" visual quirk we'd then have to
 *   document and live with. Container drag has none of that: pin the
 *   container's top-left, children flow inside via the existing auto-layout
 *   walk. Slice 8 (palette insert) will reopen leaf positioning when it
 *   actually pays rent — a newly dropped step needs a starting coordinate.
 *
 * Persistence shape in localStorage: the entire `LayoutMap` is one JSON blob
 * under `cryptographer.layouts`. Per-spec partitioning lives in the keys.
 * No pruning of stale stepIds (e.g. after a structural mutator removed a
 * step) — pruning is risk surface, localStorage is cheap, stale entries are
 * invisible to the renderer (un-referenced positions never lay anything out).
 *
 * Public API mirrors the established store pattern (cf. `stores/format.ts`,
 * `stores/view-mode.ts`): read via `useLayoutMap()`, write via small
 * dedicated setters that update the signal AND persist atomically.
 */

import type { LayoutSpec } from "@/core/document";
import { createSignal } from "solid-js";

const STORAGE_KEY = "cryptographer.layouts";

/** All layouts in one map: spec.id → LayoutSpec. Persisted as one JSON blob. */
export type LayoutMap = { readonly [specId: string]: LayoutSpec };

/**
 * Read the persisted layouts from localStorage. Defensive against:
 *   - missing localStorage (vitest's node env)
 *   - storage-quota / private-mode throws
 *   - corrupted JSON (older app, hand-edited storage)
 *   - the right JSON shape but wrong type (defensive deep-check before trusting)
 *
 * On any failure: return an empty map and continue. Layout is non-critical
 * UX state; the user's session shouldn't break because their browser refused
 * to load it.
 */
const loadInitial = (): LayoutMap => {
  try {
    if (typeof localStorage === "undefined") return {};
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    // Trust but lightly verify: each value must look like a LayoutSpec
    // (object with positions + collapsedGroups + flowDirection). Failed
    // entries are silently dropped — better than a hard error on boot.
    const out: { [specId: string]: LayoutSpec } = {};
    for (const [specId, value] of Object.entries(parsed)) {
      if (isLayoutSpec(value)) out[specId] = value;
    }
    return out;
  } catch {
    // Storage access denied, JSON.parse failed, etc.
    return {};
  }
};

/**
 * Lightweight structural check for a LayoutSpec. Not a full schema validation
 * (Slice 3's Zod schema is the authoritative one for file I/O); this is the
 * "trust but verify the broad shape" pass for localStorage rehydration.
 */
const isLayoutSpec = (v: unknown): v is LayoutSpec => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  if (typeof o.positions !== "object" || o.positions === null) return false;
  if (!Array.isArray(o.collapsedGroups)) return false;
  if (o.flowDirection !== "ltr") return false;
  return true;
};

const [layoutMap, setLayoutMapSignal] = createSignal<LayoutMap>(loadInitial());

/** Reactive read of the full layout map. GraphView consumes via createMemo. */
export const useLayoutMap = () => layoutMap;

/**
 * Non-reactive snapshot read for the active spec. Convenience for code
 * paths (e.g. App's `buildSaveText`) that don't need reactivity, just the
 * current value at call time.
 */
export const getLayoutForSpec = (specId: string): LayoutSpec | null => {
  const m = layoutMap();
  return m[specId] ?? null;
};

/** Empty-layout sentinel used when a setter starts from a missing entry. */
const emptyLayout = (): LayoutSpec => ({
  positions: {},
  collapsedGroups: [],
  flowDirection: "ltr",
});

/**
 * Persist the in-memory map to localStorage. Best-effort: failures are
 * swallowed since the in-memory state still works for the session.
 */
const persist = (map: LayoutMap): void => {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
    }
  } catch {
    // Quota / private-mode / disabled cookies. Ignore.
  }
};

/**
 * Pin one node's position. Used by GraphView's drag handler — every
 * pointermove updates this, the signal change triggers GraphView's
 * layout memo, and the new position renders on the next animation frame.
 *
 * Per Slice 6's container-only-drag scope: callers pass a CONTAINER id
 * (group/iterate) here. The store doesn't enforce that — it'll happily
 * pin a leaf id too — but the GraphView only wires pointer events to
 * container rects, so leaves go un-pinned in practice.
 */
export const setNodePosition = (specId: string, nodeId: string, x: number, y: number): void => {
  const current = layoutMap()[specId] ?? emptyLayout();
  const next: LayoutSpec = {
    positions: { ...current.positions, [nodeId]: { x, y } },
    collapsedGroups: current.collapsedGroups,
    flowDirection: current.flowDirection,
  };
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * Toggle a container's collapsed state. If currently collapsed → uncollapse;
 * if not → add to collapsed set. Used by the container header's chevron click.
 */
export const toggleCollapse = (specId: string, containerId: string): void => {
  const current = layoutMap()[specId] ?? emptyLayout();
  const set = new Set(current.collapsedGroups);
  if (set.has(containerId)) {
    set.delete(containerId);
  } else {
    set.add(containerId);
  }
  const next: LayoutSpec = {
    positions: current.positions,
    collapsedGroups: [...set],
    flowDirection: current.flowDirection,
  };
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * Load-boundary setter: replace the layout for one spec wholesale. Called
 * by `handleLoadFromText` in App.tsx when a document's `layout` sidecar is
 * present. Empty layouts are dropped from the map (so a load with no layout
 * sidecar resets that spec's persisted layout to "auto").
 */
export const setLayoutForSpec = (specId: string, layout: LayoutSpec | null): void => {
  const map = { ...layoutMap() };
  if (layout === null || !hasUserLayout(layout)) {
    delete (map as { [specId: string]: LayoutSpec })[specId];
  } else {
    (map as { [specId: string]: LayoutSpec })[specId] = layout;
  }
  setLayoutMapSignal(map);
  persist(map);
};

/** Drop one spec's layout (also a localStorage write). Reserved for tests. */
export const clearLayoutForSpec = (specId: string): void => {
  const map = { ...layoutMap() };
  delete (map as { [specId: string]: LayoutSpec })[specId];
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * True iff the user has actually customized the layout — at least one pinned
 * position OR at least one collapsed container. Used by `buildSaveText` to
 * gate the `layout` sidecar: spec-only saves stay byte-stable when nothing
 * has been dragged (the Slice 5 byte-stability test depends on this).
 */
export const hasUserLayout = (layout: LayoutSpec | null): boolean => {
  if (!layout) return false;
  return Object.keys(layout.positions).length > 0 || layout.collapsedGroups.length > 0;
};

/** Hard reset for tests. Production code never calls this. */
export const __resetLayoutsForTests = (): void => {
  setLayoutMapSignal({});
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
