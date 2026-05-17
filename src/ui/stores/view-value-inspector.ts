/**
 * View store for the value-inspector panel.
 *
 * **Click-only.** No hover. The user clicks an element on the graph
 * canvas → the matching target lands in `selectedTarget`. Clicking the
 * same element again clears the selection. Clicking a different
 * element replaces it.
 *
 * **Selectable elements:**
 *   - Edges — identified by `${from}|${to}|${auxKey}|${kind}` string keys.
 *   - Nodes — leaf stepIds, endpoint-pill ids (`__cipher_input__` /
 *     `__cipher_output__`), and synthetic block-chip ids
 *     (`${iterateId}@block${i}`). Identified by the raw id string.
 *
 * The discriminated `ValueInspectorTarget` keeps the two kinds distinct
 * so the lookup helper dispatches to either `lookupEdgeValue` or
 * `lookupNodeValue` without an ambiguous "this looks like an edge key
 * because it has a pipe in it" branch.
 *
 * The inspector panel reads the selected target and looks up the value
 * via the matching helper in `core/edge-value-lookup.ts`. We encode/
 * decode at the boundary so the store carries primitive shapes (cheap
 * signal equality) without allocating new GraphEdge objects per click.
 *
 * Why session-only (no localStorage): UI state for a click-driven
 * affordance doesn't belong in `LayoutSpec` (the byte-stable share-URL
 * surface) and isn't useful to persist across reloads. The panel starts
 * collapsed; the user opens it when they want to inspect.
 *
 * Selection behavior, stated explicitly because re-click semantics are
 * easy to get wrong:
 *
 *   - Clicking with nothing selected → selects.
 *   - Clicking the SAME element while selected → un-selects.
 *   - Clicking a DIFFERENT element while selected → selection moves.
 *   - Auto-opens the panel on click: an explicit "I want to inspect
 *     this" signal that the collapsed panel would quietly absorb is
 *     confusing.
 *
 * The selection is cleared automatically on spec.id change (e.g. cipher
 * swap) — see `GraphView.tsx`'s effect that watches `spec().id`. A
 * selected target from a prior spec points at ids that no longer
 * exist; letting it linger would render "missing" against stale
 * identity.
 */

import type { GraphEdge } from "@/core/graph";
import { createSignal } from "solid-js";

/**
 * Encode a `GraphEdge` to its identity key. The format is stable across
 * sessions but not persisted anywhere — used only for in-memory signal
 * comparisons. Order: from → to → auxKey → kind, separated by `|`.
 */
export const encodeEdgeKey = (edge: GraphEdge): string =>
  `${edge.from}|${edge.to}|${edge.auxKey}|${edge.kind}`;

/**
 * Decode an edge key produced by `encodeEdgeKey`. Returns `null` for
 * malformed input — every caller checks for null rather than throwing,
 * because the value comes from a signal and a brief mismatch during
 * spec swaps shouldn't crash the renderer.
 *
 * Defensive against pipe characters in spec ids — spec ids are
 * lowercase + dot + dash, no pipes, so `split("|")` is safe today. If a
 * future cipher allowed pipes in ids, this would need a smarter
 * splitter. Pinned at parse time so the gotcha doesn't drift.
 */
export const decodeEdgeKey = (key: string): GraphEdge | null => {
  const parts = key.split("|");
  if (parts.length !== 4) return null;
  const [from, to, auxKey, kind] = parts;
  if (from === undefined || to === undefined || auxKey === undefined || kind === undefined) {
    return null;
  }
  if (kind !== "aux" && kind !== "state") return null;
  return { from, to, auxKey, kind };
};

/**
 * Discriminated union for the inspector's selected target. Edge keys
 * are encoded strings (round-trippable via `decodeEdgeKey`); node ids
 * are raw — they're already strings and any graph fixture identifies
 * them by exactly that string. Bundle keys carry `(from, to, kind,
 * isFeedback)` and are produced when the renderer collapses N parallel
 * aux edges into one visual.
 */
export type ValueInspectorTarget =
  | { readonly kind: "edge"; readonly key: string }
  | { readonly kind: "node"; readonly id: string }
  | { readonly kind: "bundle"; readonly key: string };

/**
 * Encode a bundle identity to its inspector key. Format:
 * `bundle:${from}|${to}|${kind}|${isFeedback ? 1 : 0}`. The `bundle:`
 * prefix is the dispatch signal that the value-inspector store uses
 * to route to the bundle variant; a `data-edge-key` carrying this
 * prefix tells the click handler "open the bundle summary."
 *
 * Why a string key (matching the edge-key choice): signals compare by
 * value; strings are cheap. The store carries the primitive, and the
 * inspector body decodes it only when it needs the constituents.
 */
export const encodeBundleKey = (
  from: string,
  to: string,
  kind: "aux" | "state",
  isFeedback: boolean,
): string => `bundle:${from}|${to}|${kind}|${isFeedback ? "1" : "0"}`;

/**
 * Decode a bundle key. Returns null for any malformed input. Mirrors
 * `decodeEdgeKey`'s defensive parsing — a brief mismatch during a
 * spec swap shouldn't crash the renderer.
 */
export const decodeBundleKey = (
  key: string,
): {
  readonly from: string;
  readonly to: string;
  readonly kind: "aux" | "state";
  readonly isFeedback: boolean;
} | null => {
  if (!key.startsWith("bundle:")) return null;
  const parts = key.slice("bundle:".length).split("|");
  if (parts.length !== 4) return null;
  const [from, to, kind, fb] = parts;
  if (from === undefined || to === undefined || kind === undefined || fb === undefined) {
    return null;
  }
  if (kind !== "aux" && kind !== "state") return null;
  if (fb !== "0" && fb !== "1") return null;
  return { from, to, kind, isFeedback: fb === "1" };
};

const [selectedTarget, setSelectedTargetSignal] = createSignal<ValueInspectorTarget | null>(null);
const [inspectorPanelOpen, setInspectorPanelOpenSignal] = createSignal<boolean>(false);
/**
 * Active aux-key inside the currently-selected BUNDLE target. Decoupled
 * from the target signal so a row click in the bundle inspector's list
 * doesn't move the canvas halo (the user picked the bundle visually —
 * jumping the halo to one constituent edge is jarring). Resolves to
 * `null` when no bundle is selected OR when the user hasn't picked a
 * row yet (in which case the inspector defaults to the first auxKey).
 *
 * Cleared automatically when `selectedTarget` changes (so a switch
 * from one bundle to another doesn't show the prior bundle's row as
 * "active"). The `__resetValueInspectorForTests` helper also clears it.
 */
const [activeBundleAuxKey, setActiveBundleAuxKeySignal] = createSignal<string | null>(null);

export const useSelectedTarget = () => selectedTarget;
export const useInspectorPanelOpen = () => inspectorPanelOpen;
export const useActiveBundleAuxKey = () => activeBundleAuxKey;
export const setActiveBundleAuxKey = (auxKey: string | null): void => {
  setActiveBundleAuxKeySignal(auxKey);
};

/**
 * True iff the given edge is currently selected. Convenience for the
 * edge renderer which only needs the boolean, not the underlying
 * target shape.
 */
export const isEdgeSelected = (edgeKey: string): boolean => {
  const t = selectedTarget();
  return t !== null && t.kind === "edge" && t.key === edgeKey;
};

/**
 * True iff the given bundle is currently selected. Mirrors
 * `isEdgeSelected` for the third selectable element type. The bundle
 * key here is the `encodeBundleKey(...)` string (with the `bundle:`
 * prefix); the edge renderer passes the same string into
 * `data-edge-key` for the bundle's hit path so the visible-path halo
 * picks up the selection.
 */
export const isBundleSelected = (bundleKey: string): boolean => {
  const t = selectedTarget();
  return t !== null && t.kind === "bundle" && t.key === bundleKey;
};

/**
 * True iff the given node is currently selected. Convenience for leaf /
 * endpoint / chip renderers which only need the boolean.
 */
export const isNodeSelected = (nodeId: string): boolean => {
  const t = selectedTarget();
  return t !== null && t.kind === "node" && t.id === nodeId;
};

const targetsEqual = (a: ValueInspectorTarget, b: ValueInspectorTarget): boolean => {
  if (a.kind === "edge" && b.kind === "edge") return a.key === b.key;
  if (a.kind === "node" && b.kind === "node") return a.id === b.id;
  if (a.kind === "bundle" && b.kind === "bundle") return a.key === b.key;
  return false;
};

/**
 * Select the given target. If it matches the currently-selected
 * target, un-selects instead (the user clicked the same element twice
 * — they wanted to "release" the selection). Otherwise replaces.
 *
 * Side effect: clears `activeBundleAuxKey` on any target change so a
 * stale row-active state from a prior bundle doesn't carry over.
 *
 * Auto-opens the panel: the click is an explicit "I want to inspect
 * this" signal, so a collapsed panel that quietly absorbs the value
 * would be confusing.
 */
export const toggleSelectedTarget = (target: ValueInspectorTarget): void => {
  setSelectedTargetSignal((prev) => (prev !== null && targetsEqual(prev, target) ? null : target));
  setActiveBundleAuxKeySignal(null);
  setInspectorPanelOpenSignal(true);
};

/**
 * Convenience: toggle a selection given an `edgeKey`-style string from
 * the renderer's `data-edge-key`. Dispatches by prefix so a single
 * call site (the EdgePath hit-path's `onClick`) can route both
 * singleton edges and bundles without the renderer caring about the
 * distinction. Bundle keys start with `bundle:`; everything else is
 * treated as a per-edge key.
 */
export const toggleSelectedEdge = (key: string): void => {
  if (key.startsWith("bundle:")) {
    toggleSelectedTarget({ kind: "bundle", key });
    return;
  }
  toggleSelectedTarget({ kind: "edge", key });
};

/** Convenience: toggle a node selection given just the node id. */
export const toggleSelectedNode = (id: string): void => {
  toggleSelectedTarget({ kind: "node", id });
};

/**
 * Convenience: toggle a bundle selection given just the bundle key.
 * Used by the bundle row's drill-down click handler when an explicit
 * bundle is in hand (no string-prefix sniffing needed).
 */
export const toggleSelectedBundle = (key: string): void => {
  toggleSelectedTarget({ kind: "bundle", key });
};

/** Clear the selection unconditionally. Used by the spec.id-watcher effect. */
export const clearSelectedTarget = (): void => {
  setSelectedTargetSignal(null);
  setActiveBundleAuxKeySignal(null);
};

export const setInspectorPanelOpen = (open: boolean): void => {
  setInspectorPanelOpenSignal(open);
};

export const toggleInspectorPanelOpen = (): void => {
  setInspectorPanelOpenSignal((prev) => !prev);
};

/** Test hard-reset. Production code never calls this. */
export const __resetValueInspectorForTests = (): void => {
  setSelectedTargetSignal(null);
  setInspectorPanelOpenSignal(false);
  setActiveBundleAuxKeySignal(null);
};
