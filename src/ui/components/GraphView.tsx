/**
 * Read-only 2D graph view of the active spec + trace.
 *
 * Slice 2 of the 2D editor plan. The graph derivation in `core/graph.ts`
 * gives us a logical (nodes, containers, edges) shape; this component lays
 * it out and renders it as SVG. No drag, no editing, no palette — clicking
 * a leaf node moves the trace scrubber to that step (via setFrame), exactly
 * like clicking a row in the sidebar StepList.
 *
 * Layout (hand-rolled, FIPS-197-flavored):
 *
 *   - **Top level and iterate bodies** flow LEFT-TO-RIGHT — time goes
 *     rightward. AES-128's spec laid out this way reads like the FIPS-197
 *     "10-round pipeline" diagram: key-expansion box on the left, the
 *     initial AddRoundKey next, then 10 round columns.
 *   - **Groups** stack their children VERTICALLY — round.1's
 *     sub-bytes / shift-rows / mix-columns / add-round-key form one tall
 *     column the eye can read top-to-bottom inside the round box.
 *   - **Containers** (groups + iterates) render as labeled rounded rects
 *     that frame their children. Iterates carry a `×N` chip in the header
 *     when `blockSpan > 1` (the multi-block ECB case).
 *   - **Edges** are simple bezier curves from source-right-center to
 *     target-left-center. The auxKey lives in a hover `<title>` element.
 *
 * The whole thing re-derives the graph reactively whenever the spec or the
 * trace changes — a 200ms-debounced spec edit shows up in this view as soon
 * as the auto-rerun lands a new trace. With no trace (pre-first-run) the
 * graph still renders the structural skeleton; only the edges are absent.
 *
 * Pan/zoom are deferred to a future slice; today the SVG is rendered at its
 * computed size inside a scrollable container, so the user just scrolls.
 */

import { type CipherGraph, type ContainerNode, deriveAuxGraph } from "@/core/graph";
import { For, Show, createMemo } from "solid-js";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";

// ─── Layout constants ──────────────────────────────────────────────────────
// All in CSS pixels. Hand-tuned for AES-128's spec to fit "look like a cipher
// diagram" out of the box. Stable across other ciphers because the layout
// rules are uniform — Speck (flat, 23 leaves) becomes a long thin strip,
// Serpent (32 groups of 3) becomes a wider strip with taller round columns.

const LEAF_W = 132;
const LEAF_H = 28;
/** Vertical gap between siblings stacked inside a group. */
const STACK_GAP = 6;
/** Horizontal gap between siblings flowing inside an iterate body / root. */
const FLOW_GAP = 16;
/** Padding inside a container (group or iterate) box. */
const CONTAINER_PAD = 10;
/** Height of the container's header band (label + optional ×N chip). */
const HEADER_H = 22;
/** Outer margin of the SVG canvas. */
const CANVAS_MARGIN = 24;

// ─── Layout ────────────────────────────────────────────────────────────────

type Box = { x: number; y: number; w: number; h: number };

/**
 * Place one node (leaf or container) with its top-left at (cursorX, cursorY)
 * and return the bounding box. Recurses into containers; writes every leaf
 * and container's final box into `out`.
 */
const layoutNode = (
  id: string,
  cursorX: number,
  cursorY: number,
  containersById: Map<string, ContainerNode>,
  out: Map<string, Box>,
): Box => {
  const container = containersById.get(id);

  if (!container) {
    // Leaf: fixed-size rectangle.
    const box: Box = { x: cursorX, y: cursorY, w: LEAF_W, h: LEAF_H };
    out.set(id, box);
    return box;
  }

  if (container.kind === "group") {
    // Vertical stack of children inside a padded, header-topped rect.
    const innerX = cursorX + CONTAINER_PAD;
    let innerY = cursorY + HEADER_H + CONTAINER_PAD;
    let maxChildW = 0;
    let lastChildBottom = innerY;
    for (const childId of container.childIds) {
      const childBox = layoutNode(childId, innerX, innerY, containersById, out);
      innerY = childBox.y + childBox.h + STACK_GAP;
      lastChildBottom = childBox.y + childBox.h;
      if (childBox.w > maxChildW) maxChildW = childBox.w;
    }
    const w = Math.max(maxChildW, LEAF_W) + 2 * CONTAINER_PAD;
    const h = lastChildBottom - cursorY + CONTAINER_PAD;
    const box: Box = { x: cursorX, y: cursorY, w, h };
    out.set(id, box);
    return box;
  }

  // Iterate: horizontal flow of children, same as the top-level root.
  let innerX = cursorX + CONTAINER_PAD;
  const innerY = cursorY + HEADER_H + CONTAINER_PAD;
  let maxChildH = 0;
  let lastChildRight = innerX;
  for (const childId of container.childIds) {
    const childBox = layoutNode(childId, innerX, innerY, containersById, out);
    innerX = childBox.x + childBox.w + FLOW_GAP;
    lastChildRight = childBox.x + childBox.w;
    if (childBox.h > maxChildH) maxChildH = childBox.h;
  }
  const w = lastChildRight - cursorX + CONTAINER_PAD;
  const h = HEADER_H + 2 * CONTAINER_PAD + maxChildH;
  const box: Box = { x: cursorX, y: cursorY, w, h };
  out.set(id, box);
  return box;
};

/** Lay out the entire root (mixed leaves + containers) as a horizontal flow. */
const layoutRoot = (
  graph: CipherGraph,
): { boxes: Map<string, Box>; canvasW: number; canvasH: number } => {
  const containersById = new Map<string, ContainerNode>();
  for (const c of graph.containers) containersById.set(c.id, c);

  const boxes = new Map<string, Box>();
  let cursorX = CANVAS_MARGIN;
  let maxH = 0;
  for (const id of graph.rootIds) {
    const box = layoutNode(id, cursorX, CANVAS_MARGIN, containersById, boxes);
    cursorX = box.x + box.w + FLOW_GAP;
    if (box.h > maxH) maxH = box.h;
  }

  return {
    boxes,
    canvasW: cursorX - FLOW_GAP + CANVAS_MARGIN,
    canvasH: maxH + 2 * CANVAS_MARGIN,
  };
};

// ─── Component ─────────────────────────────────────────────────────────────

export const GraphView = () => {
  const spec = useSpec();
  const version = useTraceVersion();

  // Re-derive on every spec OR trace change. Both signals matter:
  //   - spec edit → new nodes/containers (structural change)
  //   - trace replace → new edges + blockSpan annotations
  const graph = createMemo<CipherGraph>(() => {
    void version();
    const t = getTrace();
    // No trace yet → derive from an empty trace; the structural skeleton
    // still renders, just without edges.
    const fallback = t ?? {
      frames: [],
      finalState: { shape: "bytes" as const, bytes: new Uint8Array(0) },
      finalAux: new Map(),
    };
    return deriveAuxGraph(fallback, spec());
  });

  const layout = createMemo(() => layoutRoot(graph()));

  const containersById = createMemo(() => {
    const m = new Map<string, ContainerNode>();
    for (const c of graph().containers) m.set(c.id, c);
    return m;
  });

  /**
   * Click handler for a leaf node. Move the scrubber to the first trace
   * frame whose stepId matches the canonical (suffix-stripped) leaf id.
   * Iterate-body leaves have `:b{i}` suffixed frame ids — we just match
   * the first iteration so the user lands somewhere sensible.
   */
  const handleLeafClick = (stepId: string): void => {
    void version();
    const t = getTrace();
    if (!t) return;
    const idx = t.frames.findIndex((f) => {
      const colonIdx = f.stepId.indexOf(":b");
      const canonical = colonIdx >= 0 ? f.stepId.slice(0, colonIdx) : f.stepId;
      return canonical === stepId;
    });
    if (idx >= 0) setFrame(idx);
  };

  return (
    <div class="graph-view">
      <Show when={graph().nodes.length > 0} fallback={<div class="muted">no nodes to display</div>}>
        <svg
          class="graph-view-svg"
          width={layout().canvasW}
          height={layout().canvasH}
          viewBox={`0 0 ${layout().canvasW} ${layout().canvasH}`}
          role="img"
          aria-label="Aux-flow graph of the active cipher spec"
        >
          {/* Containers first so leaves render on top of their frames. */}
          <For each={graph().containers}>
            {(container) => {
              const box = layout().boxes.get(container.id);
              if (!box) return null;
              return <ContainerRect container={container} box={box} />;
            }}
          </For>

          {/* Edges between leaf/container centers. Drawn before leaves so the
              lines tuck under the rectangle fills. */}
          <For each={graph().edges}>
            {(edge) => {
              const fromBox = layout().boxes.get(edge.from);
              const toBox = layout().boxes.get(edge.to);
              if (!fromBox || !toBox) return null;
              return <EdgePath from={fromBox} to={toBox} auxKey={edge.auxKey} />;
            }}
          </For>

          {/* Leaves last so they sit on top. */}
          <For each={graph().nodes}>
            {(node) => {
              const box = layout().boxes.get(node.stepId);
              if (!box) return null;
              const isInsideIterate = node.containerPath.some((id) => {
                const c = containersById().get(id);
                return c?.kind === "iterate";
              });
              // exactOptionalPropertyTypes is on, so we conditionally spread
              // blockSpan rather than passing `undefined` as a real value.
              const blockSpanProps =
                isInsideIterate && node.blockSpan !== undefined
                  ? { blockSpan: node.blockSpan }
                  : {};
              return (
                <LeafRect
                  stepId={node.stepId}
                  label={shortLeafLabel(node.stepId)}
                  stepType={node.stepType}
                  box={box}
                  {...blockSpanProps}
                  onClick={() => handleLeafClick(node.stepId)}
                />
              );
            }}
          </For>
        </svg>
      </Show>
    </div>
  );
};

// ─── Pieces ────────────────────────────────────────────────────────────────

const LeafRect = (props: {
  stepId: string;
  label: string;
  stepType: string;
  box: Box;
  blockSpan?: number;
  onClick: () => void;
}) => (
  // SVG <g> can't be replaced by a semantic <button> (it'd leave the SVG
  // coordinate system). We attach both click and Enter/Space keyboard
  // handlers; biome's useSemanticElements rule then leaves us alone because
  // we deliberately don't set role="button" (which is what the rule
  // objects to in non-SVG contexts).
  <g
    class="graph-leaf"
    onClick={props.onClick}
    onKeyDown={(e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        props.onClick();
      }
    }}
  >
    <title>
      {props.stepId} ({props.stepType})
      {props.blockSpan !== undefined && props.blockSpan > 1 ? ` — ×${props.blockSpan} blocks` : ""}
    </title>
    <rect
      class="graph-leaf-rect"
      x={props.box.x}
      y={props.box.y}
      width={props.box.w}
      height={props.box.h}
      rx={4}
      ry={4}
    />
    <text
      class="graph-leaf-label"
      x={props.box.x + props.box.w / 2}
      y={props.box.y + props.box.h / 2}
      text-anchor="middle"
      dominant-baseline="central"
    >
      {props.label}
    </text>
  </g>
);

const ContainerRect = (props: { container: ContainerNode; box: Box }) => (
  <g class={`graph-container graph-container-${props.container.kind}`}>
    <title>
      {props.container.kind}: {props.container.id}
      {props.container.blockSpan !== undefined && props.container.blockSpan > 1
        ? ` — ×${props.container.blockSpan}`
        : ""}
    </title>
    <rect
      class={`graph-container-rect graph-container-rect-${props.container.kind}`}
      x={props.box.x}
      y={props.box.y}
      width={props.box.w}
      height={props.box.h}
      rx={6}
      ry={6}
    />
    <text
      class="graph-container-label"
      x={props.box.x + CONTAINER_PAD}
      y={props.box.y + HEADER_H / 2 + 1}
      dominant-baseline="central"
    >
      {props.container.label}
    </text>
    <Show
      when={
        props.container.kind === "iterate" &&
        props.container.blockSpan !== undefined &&
        props.container.blockSpan > 1
      }
    >
      <text
        class="graph-iterate-badge"
        x={props.box.x + props.box.w - CONTAINER_PAD}
        y={props.box.y + HEADER_H / 2 + 1}
        text-anchor="end"
        dominant-baseline="central"
      >
        ×{props.container.blockSpan}
      </text>
    </Show>
  </g>
);

const EdgePath = (props: { from: Box; to: Box; auxKey: string }) => {
  // Source: right-center of `from`. Target: left-center of `to`. Bezier
  // control points pulled half the horizontal distance so the curve dips
  // gently without overshooting in the (rare) right-to-left case.
  const sx = props.from.x + props.from.w;
  const sy = props.from.y + props.from.h / 2;
  const tx = props.to.x;
  const ty = props.to.y + props.to.h / 2;
  const dx = Math.max(20, Math.abs(tx - sx) / 2);
  const d = `M ${sx} ${sy} C ${sx + dx} ${sy}, ${tx - dx} ${ty}, ${tx} ${ty}`;
  return (
    <path class="graph-edge" d={d}>
      <title>{props.auxKey}</title>
    </path>
  );
};

/**
 * Display label for a leaf: the last dot-segment of the stepId. Matches the
 * StepList sidebar convention so users moving between views see the same
 * names. Falls back to the full id when there's no dot (e.g. `key-expansion`,
 * `split-blocks`).
 */
const shortLeafLabel = (stepId: string): string => {
  const lastDot = stepId.lastIndexOf(".");
  if (lastDot < 0) return stepId;
  return stepId.slice(lastDot + 1);
};
