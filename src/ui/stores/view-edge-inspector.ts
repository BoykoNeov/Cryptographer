/**
 * View store for the Slice 4 edge-inspector panel.
 *
 * Hover an edge in the graph view → its key lands in `hoveredEdgeKey`.
 * Click an edge → its key replaces `pinnedEdgeKey` (clicking the same
 * edge again clears the pin; clicking a different edge replaces it).
 * The inspector panel reads pinned-or-hovered (pin wins) and looks up
 * the value via `lookupEdgeValue` in `core/edge-value-lookup.ts`.
 *
 * Edge key format: `${from}|${to}|${auxKey}|${kind}`. Uniquely
 * identifies an edge in the post-replication graph — replicas have
 * synthetic `from` ids that differ from the original source, and
 * block-chip expansion produces distinct chip ids, so the four-tuple
 * collision-free in every shipped spec. The lookup helper also accepts
 * decomposed `GraphEdge` objects; we encode/decode at the boundary so
 * the store only juggles strings (cheap signal equality).
 *
 * Why session-only (no localStorage): the same reasoning as
 * `view-replication.ts`'s panel-open signal — UI state for a hover-only
 * affordance doesn't belong in `LayoutSpec` (the byte-stable
 * share-URL surface) and isn't useful to persist across reloads. The
 * panel starts collapsed; the user opens it when they want to inspect
 * a specific edge.
 *
 * Pin behavior, stated explicitly because it's easy to get wrong:
 *
 *   - Clicking an edge with no pin set → pin replaces hover.
 *   - Clicking the SAME edge while pinned → un-pins (back to hover-only).
 *   - Clicking a DIFFERENT edge while pinned → pin moves to the new edge.
 *   - The render priority is `pinned ?? hovered`. Hover is what the
 *     cursor is currently over; pin is the user's explicit "keep this
 *     value visible while I scrub" selection. The killer demo is "pin
 *     an edge, drag the scrubber, watch the value change frame-to-
 *     frame" — that flow doesn't work if hover wins over pin.
 *
 * The pin is cleared automatically on spec.id change (e.g. cipher
 * swap) — see `GraphView.tsx`'s effect that watches `spec().id`. A
 * pinned edge from a prior spec points at nodes that no longer exist;
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

const [hoveredEdgeKey, setHoveredEdgeKeySignal] = createSignal<string | null>(null);
const [pinnedEdgeKey, setPinnedEdgeKeySignal] = createSignal<string | null>(null);
const [inspectorPanelOpen, setInspectorPanelOpenSignal] = createSignal<boolean>(false);

export const useHoveredEdgeKey = () => hoveredEdgeKey;
export const usePinnedEdgeKey = () => pinnedEdgeKey;
export const useInspectorPanelOpen = () => inspectorPanelOpen;

/**
 * Resolved active edge key — pin wins over hover. Reading this is the
 * common case for renderers ("what should I show in the panel right
 * now?"). Returns `null` when neither pin nor hover is set.
 */
export const useActiveEdgeKey = () => () => pinnedEdgeKey() ?? hoveredEdgeKey();

export const setHoveredEdgeKey = (key: string | null): void => {
  setHoveredEdgeKeySignal(key);
};

/**
 * Pin the given edge. If the key matches the currently pinned edge,
 * un-pins instead (the user clicked the same edge twice — they wanted
 * to "release" the pin). Otherwise replaces the pin.
 *
 * Auto-opens the panel: the click is an explicit "I want to inspect
 * this" signal, so a collapsed panel that quietly absorbs the value
 * would be confusing.
 */
export const togglePinnedEdge = (key: string): void => {
  setPinnedEdgeKeySignal((prev) => (prev === key ? null : key));
  setInspectorPanelOpenSignal(true);
};

/** Clear the pin unconditionally. Used by the spec.id-watcher effect. */
export const clearPinnedEdge = (): void => {
  setPinnedEdgeKeySignal(null);
};

export const setInspectorPanelOpen = (open: boolean): void => {
  setInspectorPanelOpenSignal(open);
};

export const toggleInspectorPanelOpen = (): void => {
  setInspectorPanelOpenSignal((prev) => !prev);
};

/** Test hard-reset. Production code never calls this. */
export const __resetEdgeInspectorForTests = (): void => {
  setHoveredEdgeKeySignal(null);
  setPinnedEdgeKeySignal(null);
  setInspectorPanelOpenSignal(false);
};
