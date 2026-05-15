/**
 * View store for the value-inspector panel (formerly "edge inspector",
 * renamed when the click model dropped hover and the panel's domain
 * expanded beyond edges).
 *
 * **Click-only.** No hover. The user clicks an element on the graph
 * canvas → its identity key lands in `selectedEdgeKey` (today; the
 * next commit will discriminate edges from nodes). Clicking the same
 * element again clears the selection. Clicking a different element
 * replaces it.
 *
 * The inspector panel reads the selected key and looks up the value
 * via `lookupEdgeValue` in `core/edge-value-lookup.ts`. The four-tuple
 * `${from}|${to}|${auxKey}|${kind}` uniquely identifies an edge in the
 * post-replication graph; the lookup helper also accepts decomposed
 * `GraphEdge` objects, so we encode/decode at the boundary and keep the
 * store storing strings (cheap signal equality).
 *
 * Why session-only (no localStorage): UI state for a click-driven
 * affordance doesn't belong in `LayoutSpec` (the byte-stable share-URL
 * surface) and isn't useful to persist across reloads. The panel starts
 * collapsed; the user opens it when they want to inspect.
 *
 * Selection behavior, stated explicitly because re-click semantics are
 * easy to get wrong:
 *
 *   - Clicking an edge with no selection set → selects that edge.
 *   - Clicking the SAME edge while selected → un-selects (back to empty).
 *   - Clicking a DIFFERENT edge while selected → selection moves to the
 *     new edge.
 *   - Auto-opens the panel on click: an explicit "I want to inspect this"
 *     signal that the collapsed panel would quietly absorb is confusing.
 *
 * The selection is cleared automatically on spec.id change (e.g. cipher
 * swap) — see `GraphView.tsx`'s effect that watches `spec().id`. A
 * selected edge from a prior spec points at nodes that no longer exist;
 * letting it linger would render "missing" against stale identity.
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

const [selectedEdgeKey, setSelectedEdgeKeySignal] = createSignal<string | null>(null);
const [inspectorPanelOpen, setInspectorPanelOpenSignal] = createSignal<boolean>(false);

export const useSelectedEdgeKey = () => selectedEdgeKey;
export const useInspectorPanelOpen = () => inspectorPanelOpen;

/**
 * Select the given edge. If the key matches the currently selected edge,
 * un-selects instead (the user clicked the same edge twice — they wanted
 * to "release" the selection). Otherwise replaces.
 *
 * Auto-opens the panel: the click is an explicit "I want to inspect
 * this" signal, so a collapsed panel that quietly absorbs the value
 * would be confusing.
 */
export const toggleSelectedEdge = (key: string): void => {
  setSelectedEdgeKeySignal((prev) => (prev === key ? null : key));
  setInspectorPanelOpenSignal(true);
};

/** Clear the selection unconditionally. Used by the spec.id-watcher effect. */
export const clearSelectedEdge = (): void => {
  setSelectedEdgeKeySignal(null);
};

export const setInspectorPanelOpen = (open: boolean): void => {
  setInspectorPanelOpenSignal(open);
};

export const toggleInspectorPanelOpen = (): void => {
  setInspectorPanelOpenSignal((prev) => !prev);
};

/** Test hard-reset. Production code never calls this. */
export const __resetValueInspectorForTests = (): void => {
  setSelectedEdgeKeySignal(null);
  setInspectorPanelOpenSignal(false);
};
