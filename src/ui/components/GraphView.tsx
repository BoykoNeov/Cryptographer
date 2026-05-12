/**
 * 2D graph view of the active spec + trace, with container drag + collapse
 * (Slice 6 of the 2D editor plan).
 *
 * Slice 2 originally shipped a read-only renderer over `core/graph.ts`'s
 * `deriveAuxGraph`. Slice 6 layers two interactive affordances on top:
 *
 *   1. **Container drag + root-leaf drag.** Pointer-down on a container's
 *      header band or on a root-level leaf starts a drag; pointermove
 *      updates the layout store; pointerup commits the new position. For
 *      leaves, a sub-threshold release synthesizes the original click
 *      (which scrubs the trace) so click-to-navigate still works.
 *
 *      Why root-level only (not nested leaves): the pedagogical use case
 *      is rearranging top-level entities (key-expansion, the round
 *      groups, the per-block iterate, the standalone initial AddRoundKey).
 *      Nested leaves like `round.5.sub-bytes` keep their click-only
 *      behavior so users can't accidentally pull a single step out of
 *      its parent round's bounding box. Slice 8 (palette insert) will
 *      revisit nested-leaf positioning if it becomes useful.
 *
 *   2. **Collapse / expand.** A chevron in the container header toggles
 *      that container into `LayoutSpec.collapsedGroups`. The pure
 *      `collapseGraph` transform in `core/graph.ts` hides the children
 *      and re-routes any aux edges that crossed the boundary to terminate
 *      at the collapsed chip. Edges that lived entirely inside the
 *      container drop out (self-loop after remap).
 *
 * The whole thing still re-derives reactively from spec + trace + layout;
 * layout signal updates don't trigger the auto-rerun (different signal),
 * so dragging is responsive even on a multi-block trace.
 *
 * Click-vs-drag disambiguation: pointermove movement < 4px is treated as a
 * click (which scrubs the trace for leaves, toggles collapse on chevrons,
 * starts no drag). Above threshold, the click handler is suppressed.
 */

import { type CipherGraph, type ContainerNode, collapseGraph, deriveAuxGraph } from "@/core/graph";
import { For, Show, createMemo } from "solid-js";
import { setNodePosition, toggleCollapse, useLayoutMap } from "../stores/layout";
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
/** Pixel threshold above which a pointer event is a drag, not a click. */
const DRAG_THRESHOLD_PX = 4;
/** Width of the collapse-chevron hit area inside the container header. */
const CHEVRON_W = 16;
/**
 * Pixel inset from the consumer box's left edge to the arrowhead tip.
 * Without this, the marker renders flush with the box and visually
 * penetrates the rectangle's stroke. 6px gives a clean visible gap.
 */
const ARROW_INSET = 6;

// ─── Layout ────────────────────────────────────────────────────────────────

type Box = { x: number; y: number; w: number; h: number };

/**
 * Place one node (leaf or container) with its top-left at (cursorX, cursorY)
 * and return the bounding box. Recurses into containers; writes every leaf
 * and container's final box into `out`.
 *
 * Pinned containers (those with a user-dragged position in `pinned`) use
 * their pinned (x, y) as the top-left instead of (cursorX, cursorY). Their
 * children still flow inside relative to that top-left.
 */
const layoutNode = (
  id: string,
  cursorX: number,
  cursorY: number,
  containersById: Map<string, ContainerNode>,
  pinned: ReadonlyMap<string, { x: number; y: number }>,
  out: Map<string, Box>,
): Box => {
  const container = containersById.get(id);
  const pin = pinned.get(id);
  const startX = pin?.x ?? cursorX;
  const startY = pin?.y ?? cursorY;

  if (!container) {
    // Leaf: fixed-size rectangle.
    const box: Box = { x: startX, y: startY, w: LEAF_W, h: LEAF_H };
    out.set(id, box);
    return box;
  }

  // Collapsed container: render as a leaf-sized chip; skip child recursion.
  // `collapseGraph` already cleared childIds for collapsed containers, so
  // this check is `childIds.length === 0` rather than a separate flag —
  // belt and braces, since an iterate with zero body children would also
  // hit this branch (and render correctly as an empty chip).
  if (container.childIds.length === 0) {
    const box: Box = { x: startX, y: startY, w: LEAF_W, h: LEAF_H };
    out.set(id, box);
    return box;
  }

  if (container.kind === "group") {
    // Vertical stack of children inside a padded, header-topped rect.
    const innerX = startX + CONTAINER_PAD;
    let innerY = startY + HEADER_H + CONTAINER_PAD;
    let maxChildW = 0;
    let lastChildBottom = innerY;
    for (const childId of container.childIds) {
      const childBox = layoutNode(childId, innerX, innerY, containersById, pinned, out);
      innerY = childBox.y + childBox.h + STACK_GAP;
      lastChildBottom = childBox.y + childBox.h;
      if (childBox.w > maxChildW) maxChildW = childBox.w;
    }
    const w = Math.max(maxChildW, LEAF_W) + 2 * CONTAINER_PAD;
    const h = lastChildBottom - startY + CONTAINER_PAD;
    const box: Box = { x: startX, y: startY, w, h };
    out.set(id, box);
    return box;
  }

  // Iterate: horizontal flow of children, same as the top-level root.
  let innerX = startX + CONTAINER_PAD;
  const innerY = startY + HEADER_H + CONTAINER_PAD;
  let maxChildH = 0;
  let lastChildRight = innerX;
  for (const childId of container.childIds) {
    const childBox = layoutNode(childId, innerX, innerY, containersById, pinned, out);
    innerX = childBox.x + childBox.w + FLOW_GAP;
    lastChildRight = childBox.x + childBox.w;
    if (childBox.h > maxChildH) maxChildH = childBox.h;
  }
  const w = lastChildRight - startX + CONTAINER_PAD;
  const h = HEADER_H + 2 * CONTAINER_PAD + maxChildH;
  const box: Box = { x: startX, y: startY, w, h };
  out.set(id, box);
  return box;
};

/**
 * Lay out the entire root (mixed leaves + containers) as a horizontal flow.
 *
 * Pinned root-level entries use their pinned coords for placement BUT still
 * advance the cursor by their natural width — so un-pinned siblings stay in
 * their original slots instead of sliding leftward into the vacated space.
 * (Slice 6 originally skipped cursor advancement on pin; that caused a
 * visible reflow when only some siblings were pinned: drag round.5 and
 * round.6 collapsed into round.5's slot, round.7 into round.6's, etc.)
 *
 * Canvas extent tracks the max right/bottom across all boxes (pinned or
 * not), so dragging far right just grows the SVG to fit.
 */
const layoutRoot = (
  graph: CipherGraph,
  pinned: ReadonlyMap<string, { x: number; y: number }>,
): { boxes: Map<string, Box>; canvasW: number; canvasH: number } => {
  const containersById = new Map<string, ContainerNode>();
  for (const c of graph.containers) containersById.set(c.id, c);

  const boxes = new Map<string, Box>();
  let cursorX = CANVAS_MARGIN;
  let maxRight = CANVAS_MARGIN;
  let maxBottom = CANVAS_MARGIN;
  for (const id of graph.rootIds) {
    // Capture the cursor BEFORE layoutNode — that's the natural-flow X
    // for this root entity, used for cursor advancement even when the
    // entity is pinned somewhere else. box.w is content-derived (depends
    // on children, not on this entity's pin), so it's safe to use as the
    // natural width for the advancement step.
    const naturalX = cursorX;
    const box = layoutNode(id, cursorX, CANVAS_MARGIN, containersById, pinned, boxes);
    cursorX = naturalX + box.w + FLOW_GAP;
    const right = box.x + box.w;
    const bottom = box.y + box.h;
    if (right > maxRight) maxRight = right;
    if (bottom > maxBottom) maxBottom = bottom;
  }

  return {
    boxes,
    canvasW: maxRight + CANVAS_MARGIN,
    canvasH: maxBottom + CANVAS_MARGIN,
  };
};

// ─── Component ─────────────────────────────────────────────────────────────

export const GraphView = () => {
  const spec = useSpec();
  const version = useTraceVersion();
  const layoutMap = useLayoutMap();

  /** Active spec's persisted layout, or null if none yet. */
  const activeLayout = createMemo(() => {
    const m = layoutMap();
    return m[spec().id] ?? null;
  });

  /** Set of collapsed container ids for the active spec (memoized). */
  const collapsedSet = createMemo<ReadonlySet<string>>(() => {
    const l = activeLayout();
    return l ? new Set(l.collapsedGroups) : new Set();
  });

  /** Map of pinned positions for the active spec (memoized). */
  const pinnedMap = createMemo<ReadonlyMap<string, { x: number; y: number }>>(() => {
    const l = activeLayout();
    if (!l) return new Map();
    const m = new Map<string, { x: number; y: number }>();
    for (const [id, p] of Object.entries(l.positions)) m.set(id, p);
    return m;
  });

  // Re-derive on every spec OR trace change. Both signals matter:
  //   - spec edit → new nodes/containers (structural change)
  //   - trace replace → new edges + blockSpan annotations
  const rawGraph = createMemo<CipherGraph>(() => {
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

  /** Apply collapse view-transform after raw derivation. */
  const graph = createMemo<CipherGraph>(() => collapseGraph(rawGraph(), collapsedSet()));

  const layout = createMemo(() => layoutRoot(graph(), pinnedMap()));

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

  /**
   * Begin a node drag on pointerdown. Works for any node id (container
   * or leaf) — the layout engine treats leaves with pins the same as
   * containers with pins. setPointerCapture is best-effort: jsdom
   * doesn't implement it in older versions, but the window-level
   * listeners installed below keep the drag working regardless.
   *
   * If `onClickFallback` is provided, a sub-threshold pointerup (no
   * meaningful movement) fires it — that's how leaves preserve their
   * click-to-scrub behavior while ALSO being draggable when the user
   * actually drags.
   */
  const startNodeDrag = (nodeId: string, e: PointerEvent, onClickFallback?: () => void): void => {
    e.stopPropagation();
    const startBox = layout().boxes.get(nodeId);
    if (!startBox) return;
    const startClientX = e.clientX;
    const startClientY = e.clientY;
    const startBoxX = startBox.x;
    const startBoxY = startBox.y;
    let moved = false;

    const target = e.currentTarget as Element | null;
    if (
      target &&
      typeof (target as Element & { setPointerCapture?: (id: number) => void })
        .setPointerCapture === "function"
    ) {
      try {
        (target as Element & { setPointerCapture: (id: number) => void }).setPointerCapture(
          e.pointerId,
        );
      } catch {
        // Capture failed (jsdom, security restriction). Drag still works
        // via the window-level listeners below.
      }
    }

    const onMove = (ev: PointerEvent): void => {
      const dx = ev.clientX - startClientX;
      const dy = ev.clientY - startClientY;
      if (!moved && Math.abs(dx) + Math.abs(dy) > DRAG_THRESHOLD_PX) {
        moved = true;
      }
      if (!moved) return;
      // SVG viewBox is 1:1 with rendered width/height, so client-px delta
      // maps directly onto SVG-unit delta.
      setNodePosition(spec().id, nodeId, startBoxX + dx, startBoxY + dy);
    };

    const onUp = (): void => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
      if (!moved && onClickFallback) onClickFallback();
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
  };

  return (
    <div class="graph-view">
      <Show
        when={graph().nodes.length > 0 || graph().containers.length > 0}
        fallback={<div class="muted">no nodes to display</div>}
      >
        <svg
          class="graph-view-svg"
          width={layout().canvasW}
          height={layout().canvasH}
          viewBox={`0 0 ${layout().canvasW} ${layout().canvasH}`}
          role="img"
          aria-label="Aux-flow graph of the active cipher spec"
        >
          {/* Arrowhead marker definitions. One per edge kind so each can be
              tinted to match the edge stroke (state spine = solid; aux
              annotation = translucent). markerUnits=userSpaceOnUse keeps the
              marker size fixed in canvas pixels regardless of stroke width.
              `orient=auto` rotates the marker to follow the path tangent;
              `refX=8` aligns the arrow tip with the path endpoint (the path
              itself is already inset by ARROW_INSET — see EdgePath). */}
          <defs>
            <marker
              id="graph-arrow-aux"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="8"
              markerHeight="8"
              markerUnits="userSpaceOnUse"
              orient="auto"
            >
              <path class="graph-arrow-glyph-aux" d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
            <marker
              id="graph-arrow-state"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="9"
              markerHeight="9"
              markerUnits="userSpaceOnUse"
              orient="auto"
            >
              <path class="graph-arrow-glyph-state" d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
          </defs>

          {/* Containers first so leaves render on top of their frames.
              `box` is a createMemo so the JSX binding tracks layout()
              changes — without it, the captured const goes stale when
              the layout store updates (drag fires setNodePosition; the
              <For> array reference doesn't change, so row callbacks
              don't re-run; only fine-grained bindings inside the JSX
              update the DOM). Same shape for edges and leaves below.
              See CLAUDE.md's "Solid `For` callbacks aren't reactive
              scopes" note. */}
          <For each={graph().containers}>
            {(container) => {
              const box = createMemo(() => layout().boxes.get(container.id));
              return (
                <Show when={box()}>
                  {(b) => (
                    <ContainerRect
                      container={container}
                      box={b()}
                      isCollapsed={collapsedSet().has(container.id)}
                      onDragStart={(e) => startNodeDrag(container.id, e)}
                      onToggleCollapse={() => toggleCollapse(spec().id, container.id)}
                    />
                  )}
                </Show>
              );
            }}
          </For>

          {/* Edges between leaf/container centers. Drawn before leaves so the
              lines tuck under the rectangle fills. */}
          <For each={graph().edges}>
            {(edge) => {
              const fromBox = createMemo(() => layout().boxes.get(edge.from));
              const toBox = createMemo(() => layout().boxes.get(edge.to));
              return (
                <Show when={fromBox() && toBox()}>
                  <EdgePath
                    // biome-ignore lint/style/noNonNullAssertion: <Show> guard above
                    from={fromBox()!}
                    // biome-ignore lint/style/noNonNullAssertion: <Show> guard above
                    to={toBox()!}
                    auxKey={edge.auxKey}
                    kind={edge.kind}
                  />
                </Show>
              );
            }}
          </For>

          {/* Leaves last so they sit on top. Root-level leaves (those with
              empty containerPath — e.g. AES's `key-expansion`,
              `initial.add-round-key`) are draggable; nested leaves keep
              their click-only behavior so users don't accidentally pull
              `round.5.sub-bytes` out of its parent group. The single
              `startNodeDrag` handler covers both: when draggable, drag +
              click; when not, an explicit click handler stays on the <g>. */}
          <For each={graph().nodes}>
            {(node) => {
              const box = createMemo(() => layout().boxes.get(node.stepId));
              const isInsideIterate = node.containerPath.some((id) => {
                const c = containersById().get(id);
                return c?.kind === "iterate";
              });
              const isRootLevel = node.containerPath.length === 0;
              // exactOptionalPropertyTypes is on, so we conditionally spread
              // blockSpan rather than passing `undefined` as a real value.
              const blockSpanProps =
                isInsideIterate && node.blockSpan !== undefined
                  ? { blockSpan: node.blockSpan }
                  : {};
              // Conditional spread for the drag handler — only present on
              // root-level leaves. Nested leaves get a plain onClick.
              const dragProps = isRootLevel
                ? {
                    onPointerDown: (e: PointerEvent) =>
                      startNodeDrag(node.stepId, e, () => handleLeafClick(node.stepId)),
                  }
                : {};
              return (
                <Show when={box()}>
                  {(b) => (
                    <LeafRect
                      stepId={node.stepId}
                      label={shortLeafLabel(node.stepId)}
                      stepType={node.stepType}
                      box={b()}
                      draggable={isRootLevel}
                      {...blockSpanProps}
                      {...dragProps}
                      onClick={() => handleLeafClick(node.stepId)}
                    />
                  )}
                </Show>
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
  draggable: boolean;
  /** Present only when draggable. The parent wires this to `startNodeDrag`
   * with the leaf's onClick as the sub-threshold fallback, so clicks still
   * scrub the trace and drags pin the position. */
  onPointerDown?: (e: PointerEvent) => void;
  /** Used by the keyboard handler always; also used by mouse when not
   * draggable (a click that didn't go through the drag handler). */
  onClick: () => void;
}) => {
  // SVG <g> can't be replaced by a semantic <button> (it'd leave the SVG
  // coordinate system). We attach pointer + keyboard handlers; biome's
  // useSemanticElements rule then leaves us alone because we deliberately
  // don't set role="button" (which is what the rule objects to in non-SVG
  // contexts).
  //
  // Click semantics:
  //   - draggable: the parent's pointerdown handler synthesizes the click
  //     on sub-threshold release via the onClickFallback path. We do NOT
  //     attach onClick to the <g> in that case, because pointerdown +
  //     onClickFallback fully covers it (and adding onClick would fire
  //     twice on a real click).
  //   - non-draggable: plain onClick (the legacy behavior). pointerdown
  //     isn't wired so the click flows through the browser as before.
  return (
    <g
      class={`graph-leaf${props.draggable ? " graph-leaf-draggable" : ""}`}
      onPointerDown={props.onPointerDown}
      onClick={props.draggable ? undefined : props.onClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onClick();
        }
      }}
    >
      <title>
        {props.stepId} ({props.stepType})
        {props.blockSpan !== undefined && props.blockSpan > 1
          ? ` — ×${props.blockSpan} blocks`
          : ""}
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
};

const ContainerRect = (props: {
  container: ContainerNode;
  box: Box;
  isCollapsed: boolean;
  onDragStart: (e: PointerEvent) => void;
  onToggleCollapse: () => void;
}) => {
  // Chevron sits at the right edge of the header band; clicking it doesn't
  // start a drag. The rest of the header is the drag handle.
  return (
    <g class={`graph-container graph-container-${props.container.kind}`}>
      <title>
        {props.container.kind}: {props.container.id}
        {props.container.blockSpan !== undefined && props.container.blockSpan > 1
          ? ` — ×${props.container.blockSpan}`
          : ""}
      </title>
      <rect
        class={`graph-container-rect graph-container-rect-${props.container.kind}${
          props.isCollapsed ? " graph-container-rect-collapsed" : ""
        }`}
        x={props.box.x}
        y={props.box.y}
        width={props.box.w}
        height={props.box.h}
        rx={6}
        ry={6}
      />
      {/* Header drag-handle band. Sits over the top HEADER_H pixels of the
          container rect; pointer-events="all" so it captures pointerdown
          before the child leaves do. */}
      <rect
        class="graph-container-header"
        x={props.box.x}
        y={props.box.y}
        width={Math.max(0, props.box.w - CHEVRON_W)}
        height={HEADER_H}
        fill="transparent"
        onPointerDown={(e) => props.onDragStart(e)}
        data-testid={`graph-container-header-${props.container.id}`}
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
          x={props.box.x + props.box.w - CONTAINER_PAD - CHEVRON_W}
          y={props.box.y + HEADER_H / 2 + 1}
          text-anchor="end"
          dominant-baseline="central"
        >
          ×{props.container.blockSpan}
        </text>
      </Show>
      {/* Chevron hit area on the right side of the header band. Clicking
          toggles collapse via the layout store. */}
      <g
        class="graph-container-chevron"
        onClick={(e) => {
          e.stopPropagation();
          props.onToggleCollapse();
        }}
        onKeyDown={(e) => {
          // Mirrors the LeafRect pattern: Enter and Space toggle collapse
          // for keyboard users. biome's useKeyWithClickEvents enforces it.
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            props.onToggleCollapse();
          }
        }}
        data-testid={`graph-container-chevron-${props.container.id}`}
      >
        <rect
          x={props.box.x + props.box.w - CHEVRON_W}
          y={props.box.y}
          width={CHEVRON_W}
          height={HEADER_H}
          fill="transparent"
        />
        <text
          class="graph-container-chevron-glyph"
          x={props.box.x + props.box.w - CHEVRON_W / 2}
          y={props.box.y + HEADER_H / 2 + 1}
          text-anchor="middle"
          dominant-baseline="central"
        >
          {props.isCollapsed ? "▸" : "▾"}
        </text>
      </g>
    </g>
  );
};

const EdgePath = (props: { from: Box; to: Box; auxKey: string; kind: "aux" | "state" }) => {
  // The `d` attribute is computed via createMemo so it tracks changes to
  // props.from / props.to. Without the memo, the path string would be
  // captured once at component init — a static binding — and drags would
  // not move the arrows (the user observed: arrows only update after a
  // collapse toggle, because the toggle forces graph() to re-derive +
  // <For> to re-key, which remounts EdgePath with fresh prop values).
  //
  // Source: right-center of `from`. Target: left-center of `to`, inset by
  // ARROW_INSET so the arrowhead's tip touches the consumer box's edge
  // cleanly instead of penetrating the rectangle. Bezier control points
  // pulled half the horizontal distance so the curve dips gently without
  // overshooting in the (rare) right-to-left case.
  const d = createMemo(() => {
    const sx = props.from.x + props.from.w;
    const sy = props.from.y + props.from.h / 2;
    // Pre-inset target x; bezier control still uses the unmodified target
    // x so the curve approaches the box at the same angle as before.
    const txRaw = props.to.x;
    const ty = props.to.y + props.to.h / 2;
    const tx = txRaw - ARROW_INSET;
    const dx = Math.max(20, Math.abs(txRaw - sx) / 2);
    return `M ${sx} ${sy} C ${sx + dx} ${sy}, ${txRaw - dx} ${ty}, ${tx} ${ty}`;
  });
  return (
    <path
      class={`graph-edge graph-edge-${props.kind}`}
      d={d()}
      marker-end={`url(#graph-arrow-${props.kind})`}
    >
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
