/**
 * Adapter: CipherGraph → @xyflow/react's { nodes, edges } shape.
 *
 * Used by `XyflowGraphView.tsx` (the experimental fourth view mode that
 * sits alongside the hand-rolled SVG GraphView). This is a SPIKE adapter —
 * the goal is a Phase 1 "does xyflow render our 3-level nesting cleanly"
 * answer, not a production renderer. Things deliberately out of scope:
 *
 *   - No reuse of GraphView's layout heuristics (orthogonal-axis replicas,
 *     density rescale, drag-clamp). Naive DFS-cursor layout instead.
 *   - No interaction integration (drag-to-pin via layout store, collapse
 *     via toggleCollapse). Read-only render.
 *   - No custom edge components. Inline `style` + `animated` + `markerEnd`
 *     differentiate aux from state.
 *
 * Layout algorithm: recursive DFS. Every leaf is a fixed-size box; every
 * container is sized to fit its children's bounding box plus padding (top
 * pad reserves room for the container's label band). Children are laid
 * out left-to-right with a sibling gap. The single pass produces
 * xyflow-relative coordinates directly — when a node has a `parentId`,
 * its `position` is computed relative to the parent's top-left, which is
 * exactly what xyflow expects.
 *
 * Why this layout choice for the spike: it's the simplest thing that
 * exercises 3-level nesting (root → iterate → round-group → leaves) and
 * makes the result readable. The pedagogically-correct layout (the SVG
 * view's mix of horizontal flows for iterates + vertical stacks for
 * groups) is a Phase 2+ concern.
 */

import type { CipherGraph, ContainerNode, EdgeKind, GraphNode } from "@/core/graph";
import type { Edge, Node } from "@xyflow/react";

// ─── Layout constants ────────────────────────────────────────────────────

/** Width / height for every leaf node. Containers compute their own size. */
const LEAF_W = 180;
const LEAF_H = 56;
/** Horizontal gap between siblings inside a container. */
const SIBLING_GAP_X = 32;
/** Vertical gap reserved when a container's children are themselves
 * containers of different heights (drives row-of-mixed-heights alignment). */
const SIBLING_GAP_Y = 16;
/** Padding inside a container: extra left/right, more on top to leave
 * room for the container's label band, smaller on the bottom. */
const PAD_LEFT = 20;
const PAD_RIGHT = 20;
const PAD_TOP = 48;
const PAD_BOTTOM = 20;

// ─── Edge styling ────────────────────────────────────────────────────────

/**
 * Two visually-distinguished edge kinds. State edges are the pedagogical
 * spine — thicker, darker, no animation. Aux edges annotate the dataflow
 * with round-key fan-out / IV / keystream movement — thinner, lighter,
 * animated dashed marching ants so the eye reads aux flow as "movement"
 * vs. the spine as "structure."
 */
const STYLE_BY_EDGE_KIND: Readonly<Record<EdgeKind, { stroke: string; strokeWidth: number }>> = {
  state: { stroke: "#1e293b", strokeWidth: 2.5 },
  aux: { stroke: "#94a3b8", strokeWidth: 1.25 },
};

// ─── Internal types ──────────────────────────────────────────────────────

/** Bounding-box result returned up the recursion. */
type Box = { readonly w: number; readonly h: number };

/** Lookup tables built once before the recursion, then read throughout. */
type Index = {
  readonly leafById: ReadonlyMap<string, GraphNode>;
  readonly containerById: ReadonlyMap<string, ContainerNode>;
};

// ─── Public entry point ──────────────────────────────────────────────────

export type XyflowAdapterResult = {
  readonly nodes: readonly Node[];
  readonly edges: readonly Edge[];
};

/**
 * Convert a CipherGraph (post-`deriveAuxGraph` + any view transforms like
 * collapse / replication) into xyflow's node/edge arrays. The result is
 * stateless: feed it to `<ReactFlow nodes={...} edges={...} />` and the
 * library handles rendering.
 *
 * Stable across re-runs: same input graph → identical output (no dates,
 * no UUIDs, no implicit ordering from Map iteration order).
 */
export const cipherGraphToXyflow = (graph: CipherGraph): XyflowAdapterResult => {
  const leafById = new Map<string, GraphNode>();
  for (const n of graph.nodes) leafById.set(n.stepId, n);
  const containerById = new Map<string, ContainerNode>();
  for (const c of graph.containers) containerById.set(c.id, c);
  const idx: Index = { leafById, containerById };

  const nodes: Node[] = [];

  // Root-level cursor: walk rootIds left-to-right, accumulating x.
  let cursorX = 0;
  for (const rootId of graph.rootIds) {
    const { w } = layoutOne(rootId, undefined, cursorX, 0, idx, nodes);
    cursorX += w + SIBLING_GAP_X;
  }

  const edges: Edge[] = graph.edges.map((e) => ({
    id: `${e.kind}:${e.from}->${e.to}:${e.auxKey}`,
    source: e.from,
    target: e.to,
    type: "smoothstep",
    animated: e.kind === "aux",
    style: STYLE_BY_EDGE_KIND[e.kind],
    label: e.kind === "aux" ? e.auxKey : undefined,
  }));

  return { nodes, edges };
};

// ─── Recursive layout ────────────────────────────────────────────────────

/**
 * Place one node (leaf or container) and any descendants. Returns the
 * bounding box so the caller can advance its cursor.
 *
 * Coordinate convention: `absX` / `absY` are absolute canvas coordinates
 * (the top-left where THIS node should sit). When the node has a
 * parentId, we'd want xyflow to receive a position relative to the
 * parent's top-left — but we don't know the parent's absolute origin at
 * the time we push the child, because the parent's size (and therefore
 * its origin in the grand-parent's frame) isn't known until its children
 * are all laid out. We side-step that by computing positions in two
 * stages:
 *
 *   1. Place children with absolute coordinates while measuring the
 *      container's bounding box.
 *   2. After the container's box is known, walk the children we just
 *      pushed and SUBTRACT the container's absolute origin to convert
 *      their positions to parent-relative.
 *
 * The container itself is pushed last; its position is left absolute for
 * a top-level container and parent-relative for a nested one (we know
 * the grand-parent's absolute origin at recursion entry, so we can
 * subtract once).
 */
const layoutOne = (
  id: string,
  parentId: string | undefined,
  absX: number,
  absY: number,
  idx: Index,
  out: Node[],
): Box => {
  // ── Leaf branch ────────────────────────────────────────────────────
  const leaf = idx.leafById.get(id);
  if (leaf !== undefined) {
    const labelParts = [leaf.label];
    if (leaf.blockSpan !== undefined && leaf.blockSpan > 1) {
      labelParts.push(`(×${leaf.blockSpan})`);
    }
    const node: Node = {
      id,
      position: { x: absX, y: absY },
      width: LEAF_W,
      height: LEAF_H,
      data: { label: labelParts.join(" "), stepType: leaf.stepType, replicaOf: leaf.replicaOf },
    };
    if (parentId !== undefined) {
      node.parentId = parentId;
      node.extent = "parent";
    }
    out.push(node);
    return { w: LEAF_W, h: LEAF_H };
  }

  // ── Container branch (group OR iterate) ────────────────────────────
  const container = idx.containerById.get(id);
  if (container === undefined) {
    // Unknown id (shouldn't happen for a well-formed CipherGraph). Skip
    // rather than crash — xyflow will log a warning for any edge that
    // references this id.
    return { w: 0, h: 0 };
  }

  // Empty container (e.g. a collapsed group with childIds = []): render
  // as a small labeled chip. The collapseGraph transform produces this
  // shape intentionally.
  if (container.childIds.length === 0) {
    const node: Node = {
      id,
      position: { x: absX, y: absY },
      width: LEAF_W,
      height: LEAF_H,
      type: "group",
      data: { label: containerLabel(container), kind: container.kind },
    };
    if (parentId !== undefined) {
      node.parentId = parentId;
      node.extent = "parent";
    }
    out.push(node);
    return { w: LEAF_W, h: LEAF_H };
  }

  // Lay out children with absolute coordinates first. We track where in
  // `out` the children land so we can convert their positions to
  // container-relative after the container's size is finalized.
  const childrenStart = out.length;
  const childInteriorAbsX = absX + PAD_LEFT;
  const childInteriorAbsY = absY + PAD_TOP;
  let cursorX = childInteriorAbsX;
  let maxChildH = 0;
  for (const childId of container.childIds) {
    const { w, h } = layoutOne(childId, id, cursorX, childInteriorAbsY, idx, out);
    cursorX += w + SIBLING_GAP_X;
    if (h > maxChildH) maxChildH = h;
  }
  // Subtract one trailing gap (we added it after the final child).
  const childrenWidth = cursorX - SIBLING_GAP_X - childInteriorAbsX;
  const totalW = PAD_LEFT + childrenWidth + PAD_RIGHT;
  const totalH = PAD_TOP + maxChildH + SIBLING_GAP_Y + PAD_BOTTOM;

  // Convert the just-pushed direct children of THIS container from
  // absolute to container-relative. Grandchildren further down were
  // already converted by their immediate parent's recursive call (each
  // recursion does its own pass).
  for (let i = childrenStart; i < out.length; i++) {
    const c = out[i];
    if (c === undefined) continue;
    if (c.parentId !== id) continue; // grandchild, already relativized
    out[i] = {
      ...c,
      position: { x: c.position.x - absX, y: c.position.y - absY },
    };
  }

  const node: Node = {
    id,
    position: { x: absX, y: absY },
    width: totalW,
    height: totalH,
    type: "group",
    data: { label: containerLabel(container), kind: container.kind },
  };
  if (parentId !== undefined) {
    node.parentId = parentId;
    node.extent = "parent";
  }
  out.push(node);
  return { w: totalW, h: totalH };
};

/**
 * Container label: iterate gets `×N` suffix when blockSpan is known.
 * Mirrors the SVG view's pedagogical convention.
 */
const containerLabel = (c: ContainerNode): string => {
  if (c.kind === "iterate" && c.blockSpan !== undefined && c.blockSpan > 1) {
    return `${c.label} ×${c.blockSpan}`;
  }
  return c.label;
};
