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

import type { LayoutSpec, RelativePosition, ReplicationMode } from "@/core/document";
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
 *
 * `replicationModes` is checked loosely: if present, must be a plain object,
 * but we don't validate every entry's value shape here — the file-I/O path
 * does that via Zod, and the renderer treats unknown values as "auto" anyway.
 */
const isLayoutSpec = (v: unknown): v is LayoutSpec => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  if (typeof o.positions !== "object" || o.positions === null) return false;
  if (!Array.isArray(o.collapsedGroups)) return false;
  if (o.flowDirection !== "ltr") return false;
  if (o.replicationModes !== undefined) {
    if (
      o.replicationModes === null ||
      typeof o.replicationModes !== "object" ||
      Array.isArray(o.replicationModes)
    ) {
      return false;
    }
  }
  if (o.relativePositions !== undefined) {
    if (
      o.relativePositions === null ||
      typeof o.relativePositions !== "object" ||
      Array.isArray(o.relativePositions)
    ) {
      return false;
    }
  }
  // expandedGroups (Slice 2.6d follow-up, 2026-05-25): same array-of-
  // string shape as `collapsedGroups`. Optional — missing is fine.
  if (o.expandedGroups !== undefined && !Array.isArray(o.expandedGroups)) {
    return false;
  }
  // strokeStyles (Part A, 2026-07-09): plain object map (source id → style
  // name). Checked loosely like `replicationModes` — the file-I/O path's Zod
  // schema validates entries, and the renderer falls back to `solid` for any
  // unknown value anyway.
  if (o.strokeStyles !== undefined) {
    if (
      o.strokeStyles === null ||
      typeof o.strokeStyles !== "object" ||
      Array.isArray(o.strokeStyles)
    ) {
      return false;
    }
  }
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
 * Helper: snapshot a layout's existing `replicationModes` as a plain
 * (mutable) object so a setter can edit it without aliasing. Treats absent
 * field as empty — matches the serialization convention of omitting empty
 * modes maps.
 */
const cloneReplicationModes = (layout: LayoutSpec): { [sourceId: string]: ReplicationMode } => {
  const out: { [sourceId: string]: ReplicationMode } = {};
  if (layout.replicationModes) {
    for (const [k, v] of Object.entries(layout.replicationModes)) {
      out[k] = v;
    }
  }
  return out;
};

/**
 * Helper: snapshot a layout's `relativePositions` as a plain mutable object.
 * Same pattern as `cloneReplicationModes` — absent field treated as empty.
 */
const cloneRelativePositions = (
  layout: LayoutSpec,
): { [syntheticId: string]: RelativePosition } => {
  const out: { [syntheticId: string]: RelativePosition } = {};
  if (layout.relativePositions) {
    for (const [k, v] of Object.entries(layout.relativePositions)) {
      out[k] = v;
    }
  }
  return out;
};

/**
 * Helper: snapshot a layout's `expandedGroups` as a plain mutable array.
 * Absent field treated as empty. Mirrors the clone helpers above.
 *
 * `expandedGroups` records user-explicit-expansions of containers the
 * spec declares `defaultCollapsed: true`. Empty array is never
 * persisted (see `buildLayoutSpec` for the omission discipline).
 */
const cloneExpandedGroups = (layout: LayoutSpec): string[] => {
  return layout.expandedGroups ? [...layout.expandedGroups] : [];
};

/**
 * Helper: snapshot a layout's `strokeStyles` (per-source stroke-style name
 * overrides, Part A of the graph-legibility plan) as a plain mutable object.
 * Absent field treated as empty. Mirrors the clone helpers above. Empty map
 * is never persisted (see `buildLayoutSpec`'s omission discipline).
 */
const cloneStrokeStyles = (layout: LayoutSpec): { [sourceId: string]: string } => {
  const out: { [sourceId: string]: string } = {};
  if (layout.strokeStyles) {
    for (const [k, v] of Object.entries(layout.strokeStyles)) {
      out[k] = v;
    }
  }
  return out;
};

/**
 * Compose a LayoutSpec, omitting `replicationModes` / `relativePositions` /
 * `expandedGroups` / `strokeStyles` entirely when empty. Empty objects /
 * arrays would still serialize to `{}` / `[]` — present-but-empty produces
 * different bytes than absent, defeating the byte-stability gate that
 * spec-only saves depend on. Centralized here so every setter that rebuilds
 * a LayoutSpec follows the same discipline.
 *
 * **Field order is load-bearing.** `JSON.stringify` serializes in insertion
 * order and the byte-stability gate pins that order, so the optionals must
 * be spread in the fixed sequence `replicationModes → relativePositions →
 * expandedGroups → strokeStyles`. Each is conditionally spread only when
 * non-empty. (This replaced an unrolled 2^N branch matrix once a fourth
 * optional field would have pushed it to 16 branches — conditional-spread
 * is called on drag/edit, not a hot loop, so the earlier monomorphism
 * concern doesn't apply.) `strokeStyles` is a REQUIRED positional param
 * (no default) so `tsc` flags any call site that forgets it.
 */
const buildLayoutSpec = (
  positions: { readonly [stepId: string]: { readonly x: number; readonly y: number } },
  collapsedGroups: readonly string[],
  flowDirection: "ltr",
  replicationModes: { [sourceId: string]: ReplicationMode },
  relativePositions: { [syntheticId: string]: RelativePosition },
  expandedGroups: readonly string[],
  strokeStyles: { [sourceId: string]: string },
): LayoutSpec => {
  return {
    positions,
    collapsedGroups,
    flowDirection,
    ...(Object.keys(replicationModes).length > 0 ? { replicationModes } : {}),
    ...(Object.keys(relativePositions).length > 0 ? { relativePositions } : {}),
    ...(expandedGroups.length > 0 ? { expandedGroups } : {}),
    ...(Object.keys(strokeStyles).length > 0 ? { strokeStyles } : {}),
  };
};

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
  const next = buildLayoutSpec(
    { ...current.positions, [nodeId]: { x, y } },
    current.collapsedGroups,
    current.flowDirection,
    cloneReplicationModes(current),
    cloneRelativePositions(current),
    cloneExpandedGroups(current),
    cloneStrokeStyles(current),
  );
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * Remove one node's absolute pin (back to algorithmic flow placement). Used
 * by the per-container ↺ reset affordance — the mirror of
 * `clearRelativePosition` for absolute pins. If clearing this entry leaves
 * the layout entirely empty, drops the spec's map entry to keep
 * `cryptographer.layouts` byte-stable.
 */
export const clearNodePosition = (specId: string, nodeId: string): void => {
  const current = layoutMap()[specId];
  if (!current) return;
  if (current.positions[nodeId] === undefined) return;
  const positions = { ...current.positions };
  delete positions[nodeId];
  const next = buildLayoutSpec(
    positions,
    current.collapsedGroups,
    current.flowDirection,
    cloneReplicationModes(current),
    cloneRelativePositions(current),
    cloneExpandedGroups(current),
    cloneStrokeStyles(current),
  );
  if (!hasUserLayout(next)) {
    const map = { ...layoutMap() };
    delete (map as { [specId: string]: LayoutSpec })[specId];
    setLayoutMapSignal(map);
    persist(map);
    return;
  }
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * Pin one node's RELATIVE offset (delta from its auto-laid position). Used
 * for synthetic ids — aux replicas (`${source}@->${consumer}`) and block
 * chips (`${iterateId}@block${i}`) — whose anchor is another node. The
 * layout engine adds `(dx, dy)` to the anchor-derived auto position on each
 * pass, so dragging the consumer carries the chip along.
 *
 * The store doesn't enforce that callers pass a synthetic id; the GraphView
 * gates this to replica / block-chip nodes by construction. Pinning a real
 * step id here would still work, but the layout engine only consults
 * `relativePositions` at the replica / chip placement sites, so the entry
 * would have no rendering effect.
 *
 * See `docs/plans/draggable-replicas.md` for the full design.
 */
export const setRelativePosition = (
  specId: string,
  nodeId: string,
  dx: number,
  dy: number,
): void => {
  const current = layoutMap()[specId] ?? emptyLayout();
  const relatives = cloneRelativePositions(current);
  relatives[nodeId] = { dx, dy };
  const next = buildLayoutSpec(
    current.positions,
    current.collapsedGroups,
    current.flowDirection,
    cloneReplicationModes(current),
    relatives,
    cloneExpandedGroups(current),
    cloneStrokeStyles(current),
  );
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * Remove one node's relative pin (back to algorithmic placement). Used by
 * the per-node × reset affordance. If clearing this entry leaves the
 * layout entirely empty (no positions, no collapsed, no modes, no other
 * relatives), drops the spec's entry from the map — same byte-stability
 * discipline as `setReplicationMode(null)`.
 */
export const clearRelativePosition = (specId: string, nodeId: string): void => {
  const current = layoutMap()[specId];
  if (!current) return;
  if (!current.relativePositions || current.relativePositions[nodeId] === undefined) return;
  const relatives = cloneRelativePositions(current);
  delete relatives[nodeId];
  const next = buildLayoutSpec(
    current.positions,
    current.collapsedGroups,
    current.flowDirection,
    cloneReplicationModes(current),
    relatives,
    cloneExpandedGroups(current),
    cloneStrokeStyles(current),
  );
  if (!hasUserLayout(next)) {
    const map = { ...layoutMap() };
    delete (map as { [specId: string]: LayoutSpec })[specId];
    setLayoutMapSignal(map);
    persist(map);
    return;
  }
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * Toggle a container's collapsed state, operating over the EFFECTIVE
 * collapsed view (spec defaults ∪ user collapses − user expansions),
 * not the raw `collapsedGroups`. Used by the container header's chevron
 * click.
 *
 * `inDefaults` is whether the spec marks this container `defaultCollapsed:
 * true` — the caller has the `spec` in hand and computes this via
 * `core/spec-defaults.ts::isDefaultCollapsed`. Threading it through
 * here (instead of having the store import a spec walker) keeps the
 * layout store spec-agnostic; the store doesn't need to know which
 * cipher the user is looking at.
 *
 * The four-case flip below preserves a load-bearing **end-invariant**:
 * a container id appears in AT MOST ONE of `collapsedGroups` and
 * `expandedGroups` at any time. That keeps the effective-set algebra
 * monotone — once you know `inDefaults` and the two sets, the effective
 * state is fully determined.
 *
 * Branches:
 *
 *   `inDefaults === false` (the historical case — every shipped cipher
 *   pre-2.6d-follow-up):
 *     - If `collapsedGroups` has it: remove (user is un-collapsing
 *       their explicit collapse). `expandedGroups` is never touched
 *       (the invariant guarantees it can't contain this id).
 *     - Else: add to `collapsedGroups` (user collapses what was open).
 *
 *   `inDefaults === true` (SHA-256 round groups, first consumer):
 *     - If `expandedGroups` has it: remove (user is re-collapsing back
 *       to the spec default). Net effect: returns to the default.
 *     - Else: add to `expandedGroups` (user expands a default-collapsed
 *       container; this is the explicit override the new set records).
 *     - `collapsedGroups` is never touched in this branch — adding a
 *       redundant explicit collapse on a default-collapsed container
 *       would persist bytes that change nothing about the effective
 *       state, defeating the byte-stability discipline.
 */
export const toggleCollapse = (specId: string, containerId: string, inDefaults: boolean): void => {
  const current = layoutMap()[specId] ?? emptyLayout();
  const collapsedSet = new Set(current.collapsedGroups);
  const expandedSet = new Set(current.expandedGroups ?? []);

  if (inDefaults) {
    if (expandedSet.has(containerId)) {
      // User re-collapses back to the default. Remove the explicit
      // expansion override; the default takes over.
      expandedSet.delete(containerId);
    } else {
      // User expands a default-collapsed container. Record the explicit
      // override on `expandedGroups`; do NOT touch `collapsedGroups`
      // (the invariant).
      expandedSet.add(containerId);
    }
    // Defensive structural guard: even if the layout reached us with
    // `containerId` in BOTH sets (hand-edited JSON, or a future spec
    // rename that reclassified a container so a previously-explicit
    // entry now overlaps a default), purge it from the other set
    // unconditionally. Keeps the "never in both" invariant a hard
    // structural property of every write, not just a flow consequence
    // of starting clean.
    collapsedSet.delete(containerId);
  } else {
    if (collapsedSet.has(containerId)) {
      // User un-collapses their explicit collapse.
      collapsedSet.delete(containerId);
    } else {
      // User collapses what was open. Record on `collapsedGroups`.
      collapsedSet.add(containerId);
    }
    // Defensive structural guard — mirror of the inDefaults branch.
    expandedSet.delete(containerId);
  }

  const next = buildLayoutSpec(
    current.positions,
    [...collapsedSet],
    current.flowDirection,
    cloneReplicationModes(current),
    cloneRelativePositions(current),
    [...expandedSet],
    cloneStrokeStyles(current),
  );
  // A toggle on a default-collapsed-but-not-yet-touched container CAN
  // produce a layout with only `expandedGroups` populated, which still
  // counts as user customization (hasUserLayout returns true) and so
  // persists. Conversely, re-collapsing the last explicit expansion
  // (with no other customization) leaves the layout empty — drop the
  // entry to keep `cryptographer.layouts` byte-stable.
  if (!hasUserLayout(next)) {
    const map = { ...layoutMap() };
    delete (map as { [specId: string]: LayoutSpec })[specId];
    setLayoutMapSignal(map);
    persist(map);
    return;
  }
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * Set or clear a per-source replication-mode override (commit 5 of the
 * graph-readability sequence). Passing `null` removes the entry — falls
 * back to the implicit `"auto"` default (follow the global threshold).
 * Empty modes maps are NOT preserved on the LayoutSpec: an empty map
 * defeats the byte-stability gate because it serializes to `"replicationModes":{}`
 * (different bytes than the absent-field default). `withReplicationModes`
 * omits the field when the map is empty, keeping spec-only saves stable.
 */
export const setReplicationMode = (
  specId: string,
  sourceId: string,
  mode: ReplicationMode | null,
): void => {
  const current = layoutMap()[specId] ?? emptyLayout();
  const modes = cloneReplicationModes(current);
  if (mode === null) {
    delete modes[sourceId];
  } else {
    modes[sourceId] = mode;
  }
  const next = buildLayoutSpec(
    current.positions,
    current.collapsedGroups,
    current.flowDirection,
    modes,
    cloneRelativePositions(current),
    cloneExpandedGroups(current),
    cloneStrokeStyles(current),
  );
  // If the resulting layout is entirely empty (no pins, no collapsed, no
  // modes, no relative pins), drop the entry from the map — same byte-
  // stability discipline as `setLayoutForSpec(null)`. Otherwise just
  // write through.
  if (!hasUserLayout(next)) {
    const map = { ...layoutMap() };
    delete (map as { [specId: string]: LayoutSpec })[specId];
    setLayoutMapSignal(map);
    persist(map);
    return;
  }
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
};

/**
 * Set or clear a per-source stroke-style override (Part A of the
 * graph-legibility plan, 2026-07-09). `styleName` is a name from
 * `source-strokes.ts`'s catalogue; passing `null` removes the entry —
 * falls back to the auto-assigned stroke for that source. Empty
 * `strokeStyles` maps are NOT preserved (an empty map serializes to
 * `"strokeStyles":{}`, different bytes than the absent-field default);
 * `buildLayoutSpec` omits the field when empty, keeping spec-only saves
 * byte-stable. Mirrors `setReplicationMode` exactly, including the
 * drop-the-whole-spec-when-empty tail.
 */
export const setSourceStroke = (
  specId: string,
  sourceId: string,
  styleName: string | null,
): void => {
  const current = layoutMap()[specId] ?? emptyLayout();
  const strokes = cloneStrokeStyles(current);
  if (styleName === null) {
    delete strokes[sourceId];
  } else {
    strokes[sourceId] = styleName;
  }
  const next = buildLayoutSpec(
    current.positions,
    current.collapsedGroups,
    current.flowDirection,
    cloneReplicationModes(current),
    cloneRelativePositions(current),
    cloneExpandedGroups(current),
    strokes,
  );
  // If the resulting layout is entirely empty, drop the spec from the map —
  // same byte-stability discipline as `setReplicationMode`.
  if (!hasUserLayout(next)) {
    const map = { ...layoutMap() };
    delete (map as { [specId: string]: LayoutSpec })[specId];
    setLayoutMapSignal(map);
    persist(map);
    return;
  }
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

/**
 * Multiply every pinned position in every spec's layout by `factor`. Used by
 * `view-density.ts::setViewDensity` to keep dragged containers in their
 * "logical slot" when the user flips density — without rescaling, a pin at
 * (400, 200) saved at normal density (1.0×) stays at (400, 200) when the
 * canvas redraws at compact (0.75×), which collides with the surrounding
 * un-pinned flow that DID shrink.
 *
 * No-ops when `factor === 1.0` (e.g., flipping between two density values
 * that happen to scale the same — not possible today, but defensive) and
 * when the layout map has no positions to rescale. `Math.round` keeps the
 * stored values integer; over many flips the drift is sub-pixel and
 * invisible (3 flips ≈ ±1px on a 400-pixel coordinate).
 *
 * Does NOT touch `collapsedGroups` or `replicationModes` — those are
 * density-independent. Replication overrides are still a single map entry,
 * not coordinates.
 */
export const rescaleAllPositions = (factor: number): void => {
  if (factor === 1.0) return;
  const map = layoutMap();
  let changed = false;
  const newMap: { [specId: string]: LayoutSpec } = {};
  for (const [specId, layout] of Object.entries(map)) {
    const positionEntries = Object.entries(layout.positions);
    const relativeEntries = layout.relativePositions
      ? Object.entries(layout.relativePositions)
      : [];
    if (positionEntries.length === 0 && relativeEntries.length === 0) {
      // No coords for this spec → no rescale; pass through unchanged.
      newMap[specId] = layout;
      continue;
    }
    const newPositions: { [nodeId: string]: { x: number; y: number } } = {};
    for (const [id, p] of positionEntries) {
      newPositions[id] = {
        x: Math.round(p.x * factor),
        y: Math.round(p.y * factor),
      };
    }
    // Relative deltas are stored in viewBox units at the layout's CURRENT
    // density, same as absolute positions — so a flip to a different
    // density rescales them too. Without this, a chip pinned with delta
    // (40, 0) at density 1.0 would keep that 40-px offset at density
    // 0.75 even though the consumer's auto-position scaled to 0.75×,
    // making the chip drift to the right relative to where the user put it.
    const newRelatives: { [syntheticId: string]: RelativePosition } = {};
    for (const [id, r] of relativeEntries) {
      newRelatives[id] = {
        dx: Math.round(r.dx * factor),
        dy: Math.round(r.dy * factor),
      };
    }
    newMap[specId] = buildLayoutSpec(
      newPositions,
      layout.collapsedGroups,
      layout.flowDirection,
      cloneReplicationModes(layout),
      newRelatives,
      cloneExpandedGroups(layout),
      cloneStrokeStyles(layout),
    );
    changed = true;
  }
  if (!changed) return;
  setLayoutMapSignal(newMap);
  persist(newMap);
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
  if (Object.keys(layout.positions).length > 0) return true;
  if (layout.collapsedGroups.length > 0) return true;
  // Commit 5: replicationModes also counts. An override is meaningful even
  // when nothing has been dragged or collapsed (e.g. "force key-expansion
  // to always replicate, keep everything else auto").
  if (layout.replicationModes && Object.keys(layout.replicationModes).length > 0) return true;
  // Draggable replicas (2026-05-19): a relative pin on a chip is a
  // meaningful customization on its own.
  if (layout.relativePositions && Object.keys(layout.relativePositions).length > 0) return true;
  // Default-collapse override (Slice 2.6d follow-up, 2026-05-25):
  // expandedGroups carries explicit user-expansions of containers the
  // spec marks `defaultCollapsed: true`. A SHA-256 session where the
  // user did nothing but expand `round.5` produces a layout whose only
  // populated field is `expandedGroups: ["round.5"]` — that's
  // meaningful customization and must persist + ride through Save /
  // Share.
  if (layout.expandedGroups && layout.expandedGroups.length > 0) return true;
  // Per-source stroke-style override (Part A, 2026-07-09): a manual stroke
  // assignment is meaningful customization on its own — a session where the
  // user did nothing but restyle one source's arrows produces a layout whose
  // only populated field is `strokeStyles`, and that must persist + ride
  // through Save / Share. Same reasoning as `expandedGroups` above.
  if (layout.strokeStyles && Object.keys(layout.strokeStyles).length > 0) return true;
  return false;
};

/**
 * Apply an id-rename map to every layer of a LayoutSpec (positions,
 * collapsedGroups, replicationModes). Used by the duplicate-round
 * feature: when the spec mutator renames `round.3 → round.4`,
 * `round.4 → round.5`, etc., any pre-existing layout pin or collapsed
 * marker on the old id needs to follow the rename so the visual state
 * stays attached to the same logical container.
 *
 * Pure: returns a new LayoutSpec with the rename applied. Un-renamed
 * ids pass through unchanged. If `renames` is empty, returns the input
 * by reference for cheap no-op short-circuit.
 *
 * Implementation notes:
 *   • A collision-free rename map is assumed — if two old ids map to
 *     the same new id, the later one in the `Object.entries` order wins
 *     (positions, replicationModes). For the duplicate-round mutator
 *     this never happens: the rename map is always a strict shift of
 *     contiguous round numbers, so the destinations are all distinct.
 *   • The `replicationModes` field is omitted from the result when
 *     empty (same byte-stability discipline as `withReplicationModes`).
 */
export const renameLayoutIds = (
  layout: LayoutSpec,
  renames: ReadonlyMap<string, string>,
): LayoutSpec => {
  if (renames.size === 0) return layout;

  const newPositions: { [stepId: string]: { x: number; y: number } } = {};
  for (const [id, pos] of Object.entries(layout.positions)) {
    const newId = renames.get(id) ?? id;
    newPositions[newId] = pos;
  }

  const newCollapsedGroups = layout.collapsedGroups.map((id) => renames.get(id) ?? id);

  let newReplicationModes: { [sourceId: string]: ReplicationMode } | undefined;
  if (layout.replicationModes) {
    const remapped: { [sourceId: string]: ReplicationMode } = {};
    for (const [id, mode] of Object.entries(layout.replicationModes)) {
      const newId = renames.get(id) ?? id;
      remapped[newId] = mode;
    }
    if (Object.keys(remapped).length > 0) newReplicationModes = remapped;
  }

  // `relativePositions` keys are SYNTHETIC ids (`${source}@->${consumer}`,
  // `${iterateId}@block${i}`) that embed real step ids. Parsing those out
  // for a proper rename remap is non-trivial, and today's only rename
  // caller (the duplicate-round mutator's contiguous numeric shift)
  // doesn't move replica targets across rounds — it just shifts round
  // numbers, which doesn't rename consumers. Pass the field through
  // unchanged for now; the "no pruning of stale ids" policy already
  // documented at the top of this file applies if a future rename DOES
  // orphan entries. Documented in `docs/plans/draggable-replicas.md`
  // under "Risks (acknowledged)."
  let newRelativePositions: { [syntheticId: string]: RelativePosition } | undefined;
  if (layout.relativePositions && Object.keys(layout.relativePositions).length > 0) {
    newRelativePositions = { ...layout.relativePositions };
  }

  // `expandedGroups` (Slice 2.6d follow-up) keys real container ids,
  // same as `collapsedGroups` — apply the rename in parallel. Empty
  // result is omitted from the returned object per byte-stability
  // discipline (mirrors how `newReplicationModes` is handled above).
  let newExpandedGroups: readonly string[] | undefined;
  if (layout.expandedGroups && layout.expandedGroups.length > 0) {
    newExpandedGroups = layout.expandedGroups.map((id) => renames.get(id) ?? id);
  }

  // `strokeStyles` keys on the CANONICAL source id — the same id namespace
  // as `replicationModes` (replica nodes collapse to their origin) — so a
  // rename remaps it in parallel. Empty result is omitted per byte-stability
  // discipline. MUST be spread LAST in the return object (after
  // expandedGroups) to match `buildLayoutSpec`'s insertion order; a
  // divergence would silently change a doc's bytes on duplicate-round rename.
  let newStrokeStyles: { [sourceId: string]: string } | undefined;
  if (layout.strokeStyles && Object.keys(layout.strokeStyles).length > 0) {
    const remapped: { [sourceId: string]: string } = {};
    for (const [id, style] of Object.entries(layout.strokeStyles)) {
      const newId = renames.get(id) ?? id;
      remapped[newId] = style;
    }
    if (Object.keys(remapped).length > 0) newStrokeStyles = remapped;
  }

  return {
    positions: newPositions,
    collapsedGroups: newCollapsedGroups,
    flowDirection: layout.flowDirection,
    ...(newReplicationModes ? { replicationModes: newReplicationModes } : {}),
    ...(newRelativePositions ? { relativePositions: newRelativePositions } : {}),
    ...(newExpandedGroups ? { expandedGroups: newExpandedGroups } : {}),
    ...(newStrokeStyles ? { strokeStyles: newStrokeStyles } : {}),
  };
};

/**
 * Apply a rename map to one spec's persisted layout in place (writes
 * through the signal AND localStorage). No-op if the spec has no
 * layout yet OR the rename map is empty.
 */
export const renameSpecLayoutIds = (specId: string, renames: ReadonlyMap<string, string>): void => {
  if (renames.size === 0) return;
  const current = layoutMap()[specId];
  if (!current) return;
  const next = renameLayoutIds(current, renames);
  if (next === current) return;
  const map = { ...layoutMap(), [specId]: next };
  setLayoutMapSignal(map);
  persist(map);
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
