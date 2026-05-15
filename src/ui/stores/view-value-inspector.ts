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
 * them by exactly that string.
 */
export type ValueInspectorTarget =
  | { readonly kind: "edge"; readonly key: string }
  | { readonly kind: "node"; readonly id: string };

const [selectedTarget, setSelectedTargetSignal] = createSignal<ValueInspectorTarget | null>(null);
const [inspectorPanelOpen, setInspectorPanelOpenSignal] = createSignal<boolean>(false);

export const useSelectedTarget = () => selectedTarget;
export const useInspectorPanelOpen = () => inspectorPanelOpen;

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
  return false;
};

/**
 * Select the given target. If it matches the currently-selected
 * target, un-selects instead (the user clicked the same element twice
 * — they wanted to "release" the selection). Otherwise replaces.
 *
 * Auto-opens the panel: the click is an explicit "I want to inspect
 * this" signal, so a collapsed panel that quietly absorbs the value
 * would be confusing.
 */
export const toggleSelectedTarget = (target: ValueInspectorTarget): void => {
  setSelectedTargetSignal((prev) => (prev !== null && targetsEqual(prev, target) ? null : target));
  setInspectorPanelOpenSignal(true);
};

/** Convenience: toggle an edge selection given just the edge key. */
export const toggleSelectedEdge = (key: string): void => {
  toggleSelectedTarget({ kind: "edge", key });
};

/** Convenience: toggle a node selection given just the node id. */
export const toggleSelectedNode = (id: string): void => {
  toggleSelectedTarget({ kind: "node", id });
};

/** Clear the selection unconditionally. Used by the spec.id-watcher effect. */
export const clearSelectedTarget = (): void => {
  setSelectedTargetSignal(null);
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
};
