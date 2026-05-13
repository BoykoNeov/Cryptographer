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
import {
  ALL_VIEW_DENSITIES,
  DENSITY_SCALE,
  VIEW_DENSITY_LABELS,
  type ViewDensity,
  setViewDensity,
  useViewDensity,
} from "../stores/view-density";

// ─── Layout constants ──────────────────────────────────────────────────────
// All in CSS pixels. The size-and-gap subset scales with the active view
// density (commit 3 of the graph-readability sequence); the rest are
// density-independent because they describe affordance hit-targets (drag
// threshold, chevron width) or font-derived heuristics (label rendering)
// that don't get more legible by scaling the surrounding geometry.
//
// Why split the constants this way:
//
//   - Scaling DRAG_THRESHOLD_PX would make compact mode harder to
//     drag-versus-click (4px ≈ a deliberate flick; 3px ≈ accidental).
//   - Scaling CHEVRON_W would shrink the chevron hit area below the
//     iOS/Android 44px / desktop ~16px touch-target threshold.
//   - Scaling LABEL_PX_PER_CHAR would be a no-op: the heuristic models
//     the FONT's px-per-char, not the layout's, and the font size is
//     fixed (browser zoom is the user's accessibility lever, not us).
//   - Scaling HEADER_H + CANVAS_MARGIN is intentionally skipped so the
//     header band stays comfortable for 11px text and the canvas keeps
//     a consistent outer breathing room across densities. Reconsider
//     if a future density preset goes more extreme than 0.75×/1.25×.

/** Base (1.0×) leaf-rectangle width in CSS pixels. */
const BASE_LEAF_W = 132;
/** Base (1.0×) leaf-rectangle height. */
const BASE_LEAF_H = 28;
/** Base (1.0×) vertical gap between siblings stacked inside a group. */
const BASE_STACK_GAP = 6;
/** Base (1.0×) horizontal gap between siblings flowing inside an iterate body / root. */
const BASE_FLOW_GAP = 16;
/** Base (1.0×) padding inside a container (group or iterate) box. */
const BASE_CONTAINER_PAD = 10;
/** Height of the container's header band (label + optional ×N chip). Fixed. */
const HEADER_H = 22;
/** Outer margin of the SVG canvas. Fixed. */
const CANVAS_MARGIN = 24;
/** Pixel threshold above which a pointer event is a drag, not a click. Fixed. */
const DRAG_THRESHOLD_PX = 4;
/** Width of the collapse-chevron hit area inside the container header. Fixed. */
const CHEVRON_W = 16;
/**
 * Pixel inset from the consumer box's left edge to the arrowhead tip.
 * Without this, the marker renders flush with the box and visually
 * penetrates the rectangle's stroke. 6px gives a clean visible gap.
 */
const ARROW_INSET = 6;
/**
 * Pixel gap between the right edge of a container label and whatever sits to
 * its right (chevron or iterate badge). Keeps the truncated text from
 * kissing the chevron glyph when `textLength` compression kicks in.
 */
const LABEL_RIGHT_GAP = 4;
/**
 * Pixel width to reserve for the `×N` iterate badge when present. Sized for
 * "×NN" at 11px bold (≈22px) with a small breathing margin; over-reserving
 * a couple of pixels is preferable to letting label characters collide
 * with the badge's leftmost glyph.
 */
const ITERATE_BADGE_RESERVE_W = 28;
/**
 * Rough px-per-char at the container label's font (11px, weight 600,
 * sans-serif). Used purely as a heuristic: if the label's natural width
 * estimate is wider than the available header room, apply `textLength` to
 * clip; otherwise leave the SVG `<text>` to render at its natural size so
 * short labels don't get visually spread out by `lengthAdjust`. 7 is a
 * deliberate slight over-estimate — under-clipping (visible overflow) is
 * worse than over-clipping (a few pixels of compression nobody notices).
 */
const LABEL_PX_PER_CHAR = 7;

/**
 * Density-derived size + gap constants. The five values that scale with
 * `ViewDensity` live in this record; the fixed constants (HEADER_H,
 * CANVAS_MARGIN, etc.) stay module-scope. `layoutNode`, `layoutRoot`, and
 * `labelTextLength` take this record as a parameter so they remain pure
 * (testable without the component) AND so the component's reactive memo
 * over density propagates correctly through the layout pipeline.
 */
type LayoutConstants = {
  readonly LEAF_W: number;
  readonly LEAF_H: number;
  readonly STACK_GAP: number;
  readonly FLOW_GAP: number;
  readonly CONTAINER_PAD: number;
};

/**
 * Build the size + gap constants for a given density. "normal" returns the
 * base values byte-for-byte so the default rendering is identical to the
 * pre-density layout (and the prior label-truncation + drag tests don't
 * need to be re-baselined). `Math.round` keeps the values at integer
 * pixels — SVG accepts fractional pixels but integer x/w stays crisp on
 * non-DPR-aware browsers and avoids sub-pixel rendering artifacts at the
 * leaf rect's right edge.
 */
const layoutConstantsFor = (density: ViewDensity): LayoutConstants => {
  const scale = DENSITY_SCALE[density];
  return {
    LEAF_W: Math.round(BASE_LEAF_W * scale),
    LEAF_H: Math.round(BASE_LEAF_H * scale),
    STACK_GAP: Math.round(BASE_STACK_GAP * scale),
    FLOW_GAP: Math.round(BASE_FLOW_GAP * scale),
    CONTAINER_PAD: Math.round(BASE_CONTAINER_PAD * scale),
  };
};

/**
 * Compute the `textLength` value (in CSS pixels) that should be applied to a
 * container's header label, or `undefined` when the label fits naturally
 * and no clipping is needed.
 *
 * Why this exists: long container labels (e.g. AES-128's final round
 * "Round 10 (final, no MixColumns)" at 33 chars) overflowed the container
 * box's right edge in Slice 6 — visually past the chevron, and (until
 * `pointer-events: none` mitigated it) absorbing pointerdown events meant
 * for the underlying drag handle. SVG `textLength` + `lengthAdjust=
 * spacingAndGlyphs` is the V1 baseline: the browser shrinks the rendered
 * text to fit without us doing font measurement. The `<title>` element on
 * the parent `<g>` keeps the full label discoverable on hover.
 *
 * Available width = box width − left padding − right reserve. Right reserve
 * is the chevron always plus the `×N` iterate badge when one is rendered,
 * plus `LABEL_RIGHT_GAP` so the label doesn't visually kiss whatever sits
 * to its right.
 */
const labelTextLength = (
  container: ContainerNode,
  boxW: number,
  consts: LayoutConstants,
): number | undefined => {
  const hasIterateBadge =
    container.kind === "iterate" && container.blockSpan !== undefined && container.blockSpan > 1;
  const reserveRight =
    CHEVRON_W + LABEL_RIGHT_GAP + (hasIterateBadge ? ITERATE_BADGE_RESERVE_W : 0);
  const available = boxW - consts.CONTAINER_PAD - reserveRight;
  // Container narrower than its own affordances — nothing to clip TO. The
  // chevron/badge already eat the box; let the label render naturally and
  // count on the higher-level layout-knob work to grow the box.
  if (available <= 0) return undefined;
  const naturalEstimate = container.label.length * LABEL_PX_PER_CHAR;
  return naturalEstimate > available ? available : undefined;
};

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
  consts: LayoutConstants,
): Box => {
  const container = containersById.get(id);
  const pin = pinned.get(id);
  const startX = pin?.x ?? cursorX;
  const startY = pin?.y ?? cursorY;

  if (!container) {
    // Leaf: fixed-size rectangle.
    const box: Box = { x: startX, y: startY, w: consts.LEAF_W, h: consts.LEAF_H };
    out.set(id, box);
    return box;
  }

  // Collapsed container: render as a leaf-sized chip; skip child recursion.
  // `collapseGraph` already cleared childIds for collapsed containers, so
  // this check is `childIds.length === 0` rather than a separate flag —
  // belt and braces, since an iterate with zero body children would also
  // hit this branch (and render correctly as an empty chip).
  if (container.childIds.length === 0) {
    const box: Box = { x: startX, y: startY, w: consts.LEAF_W, h: consts.LEAF_H };
    out.set(id, box);
    return box;
  }

  if (container.kind === "group") {
    // Vertical stack of children inside a padded, header-topped rect.
    const innerX = startX + consts.CONTAINER_PAD;
    let innerY = startY + HEADER_H + consts.CONTAINER_PAD;
    let maxChildW = 0;
    let lastChildBottom = innerY;
    for (const childId of container.childIds) {
      const childBox = layoutNode(childId, innerX, innerY, containersById, pinned, out, consts);
      innerY = childBox.y + childBox.h + consts.STACK_GAP;
      lastChildBottom = childBox.y + childBox.h;
      if (childBox.w > maxChildW) maxChildW = childBox.w;
    }
    const w = Math.max(maxChildW, consts.LEAF_W) + 2 * consts.CONTAINER_PAD;
    const h = lastChildBottom - startY + consts.CONTAINER_PAD;
    const box: Box = { x: startX, y: startY, w, h };
    out.set(id, box);
    return box;
  }

  // Iterate: horizontal flow of children, same as the top-level root.
  let innerX = startX + consts.CONTAINER_PAD;
  const innerY = startY + HEADER_H + consts.CONTAINER_PAD;
  let maxChildH = 0;
  let lastChildRight = innerX;
  for (const childId of container.childIds) {
    const childBox = layoutNode(childId, innerX, innerY, containersById, pinned, out, consts);
    innerX = childBox.x + childBox.w + consts.FLOW_GAP;
    lastChildRight = childBox.x + childBox.w;
    if (childBox.h > maxChildH) maxChildH = childBox.h;
  }
  const w = lastChildRight - startX + consts.CONTAINER_PAD;
  const h = HEADER_H + 2 * consts.CONTAINER_PAD + maxChildH;
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
export const layoutRoot = (
  graph: CipherGraph,
  pinned: ReadonlyMap<string, { x: number; y: number }>,
  consts: LayoutConstants,
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
    const box = layoutNode(id, cursorX, CANVAS_MARGIN, containersById, pinned, boxes, consts);
    cursorX = naturalX + box.w + consts.FLOW_GAP;
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

/** Re-exported for tests that want to drive `layoutRoot` directly. */
export { layoutConstantsFor };

// ─── Component ─────────────────────────────────────────────────────────────

export const GraphView = () => {
  const spec = useSpec();
  const version = useTraceVersion();
  const layoutMap = useLayoutMap();
  const density = useViewDensity();

  /**
   * Size + gap constants for the active density. Memoized so the layout
   * memo below only re-runs on actual density changes (not on every
   * unrelated signal tick that flows through this component). All four
   * downstream memos (`graph`, `layout`, `containersById`) read this
   * implicitly via the consts threaded into `layoutRoot`.
   */
  const consts = createMemo(() => layoutConstantsFor(density()));

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

  const layout = createMemo(() => layoutRoot(graph(), pinnedMap(), consts()));

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
      {/* Density toolbar (commit 3 of the graph-readability sequence).
          Lives inside GraphView because density is graph-specific — the
          linear and JSON views ignore it. Uses `<fieldset>`/`<legend>` for
          the same a11y-friendly group semantics as the byte-format toggle
          in App.tsx (biome's useSemanticElements rule wants a semantic
          group element, not `<div role="group">`). Stays above the SVG so
          it remains visible even when the graph canvas is scrolled. */}
      <fieldset class="graph-view-toolbar">
        <legend class="graph-view-toolbar-label">density</legend>
        <div class="format-toggle">
          <For each={ALL_VIEW_DENSITIES}>
            {(d) => (
              <button
                type="button"
                classList={{ active: density() === d }}
                onClick={() => setViewDensity(d as ViewDensity)}
                title={`Switch graph to ${VIEW_DENSITY_LABELS[d]} density`}
              >
                {VIEW_DENSITY_LABELS[d]}
              </button>
            )}
          </For>
        </div>
      </fieldset>
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
                      consts={consts()}
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
  consts: LayoutConstants;
  onDragStart: (e: PointerEvent) => void;
  onToggleCollapse: () => void;
}) => {
  // Chevron sits at the right edge of the header band; clicking it doesn't
  // start a drag. The rest of the header is the drag handle.
  //
  // The label's `textLength` is memoized so it tracks both label changes
  // (spec edits rename a group) and box width changes (collapse toggles or
  // child resizes shrink the container). When the label fits naturally the
  // memo returns `undefined`; Solid omits the attribute, leaving the text
  // to render at its natural width — that branch is deliberate because
  // `lengthAdjust=spacingAndGlyphs` will SPREAD a short label out to fill
  // the supplied width, which would look worse than the overflow we're
  // protecting against. Depends on `consts.CONTAINER_PAD` (density-derived)
  // for the available-width arithmetic, so it also tracks density flips.
  const labelTL = createMemo(() => labelTextLength(props.container, props.box.w, props.consts));
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
        x={props.box.x + props.consts.CONTAINER_PAD}
        y={props.box.y + HEADER_H / 2 + 1}
        dominant-baseline="central"
        textLength={labelTL()}
        lengthAdjust={labelTL() === undefined ? undefined : "spacingAndGlyphs"}
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
          x={props.box.x + props.box.w - props.consts.CONTAINER_PAD - CHEVRON_W}
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
  // Exit/entry sides are chosen by geometry, not hard-coded. The arrowhead
  // already conveys flow direction, so we don't need to enforce the
  // "always right→left" rule. Two regimes:
  //
  //   - **Vertical sides** (exit bottom / enter top, or the reverse): used
  //     when the boxes overlap on the x-axis but are separated on y. This
  //     is the "stacked vertically inside an expanded group" case (AES's
  //     sub-bytes → shift-rows, every cipher's intra-round leaves). With
  //     hard-coded right→left the curve had to bulge way out past the
  //     boxes' right edges and loop back to enter from the left, passing
  //     visually BEHIND the components. Bottom→top tucks the edge into
  //     the natural inter-leaf gap.
  //
  //   - **Horizontal sides** (exit right / enter left, or reverse): the
  //     default for everything else — horizontal flow at the root, iterate
  //     bodies, cross-container fan-outs. This matches the original
  //     behavior and the FIPS-197-flavored "time flows rightward" layout.
  //
  // Inset is clamped to half the natural gap between source and target so
  // the arrowhead never crosses the source on tight gaps (the STACK_GAP=6
  // case inside groups would otherwise produce a zero-length or
  // negative-length path).
  const d = createMemo(() => {
    const { from, to } = props;

    // Axis overlap detection. Strict > rather than >= so two boxes that
    // merely touch at one edge (e.g., adjacent siblings in a flow with
    // FLOW_GAP=0, hypothetical) count as non-overlapping on that axis.
    const horizOverlap = Math.min(from.x + from.w, to.x + to.w) > Math.max(from.x, to.x);
    const vertOverlap = Math.min(from.y + from.h, to.y + to.h) > Math.max(from.y, to.y);

    // Only switch to vertical sides when boxes are *purely* vertically
    // separated (share x-range, no y-overlap). Diagonal cases keep the
    // horizontal regime so the curve travels through the inter-container
    // gap, which is the established visual pattern.
    const useVertical = horizOverlap && !vertOverlap;

    if (useVertical) {
      const fromCx = from.x + from.w / 2;
      const toCx = to.x + to.w / 2;
      const downward = to.y + to.h / 2 >= from.y + from.h / 2;
      const sx = fromCx;
      const sy = downward ? from.y + from.h : from.y;
      const tx = toCx;
      const tEdge = downward ? to.y : to.y + to.h;
      const naturalGap = downward ? to.y - (from.y + from.h) : from.y - (to.y + to.h);
      // Clamp inset so even adjacent siblings (gap = STACK_GAP = 6) get a
      // monotonic, non-self-intersecting path.
      const inset = Math.max(0, Math.min(ARROW_INSET, naturalGap / 2));
      const ty = downward ? tEdge - inset : tEdge + inset;
      // Pull magnitude proportional to the post-inset span; degenerates
      // to a straight line for very short edges (no floor — the loop
      // artifact we used to get came from over-pulling on tiny gaps).
      const span = Math.abs(ty - sy);
      const pull = Math.min(20, span * 0.5);
      const c1y = downward ? sy + pull : sy - pull;
      const c2y = downward ? ty - pull : ty + pull;
      return `M ${sx} ${sy} C ${sx} ${c1y}, ${tx} ${c2y}, ${tx} ${ty}`;
    }

    // Horizontal regime. Source exits whichever edge faces the target;
    // target enters the facing edge with inset. Pull formula matches the
    // original (max(20, |dx|/2)) so the curve aesthetic for root-level
    // and cross-container fan-outs is unchanged.
    const fromCy = from.y + from.h / 2;
    const toCy = to.y + to.h / 2;
    const rightward = to.x + to.w / 2 >= from.x + from.w / 2;
    const sx = rightward ? from.x + from.w : from.x;
    const sy = fromCy;
    const tEdge = rightward ? to.x : to.x + to.w;
    const naturalGap = rightward ? to.x - (from.x + from.w) : from.x - (to.x + to.w);
    const inset = naturalGap > 0 ? Math.min(ARROW_INSET, naturalGap / 2) : ARROW_INSET;
    const tx = rightward ? tEdge - inset : tEdge + inset;
    const ty = toCy;
    const pull = Math.max(20, Math.abs(tx - sx) / 2);
    const c1x = rightward ? sx + pull : sx - pull;
    const c2x = rightward ? tx - pull : tx + pull;
    return `M ${sx} ${sy} C ${c1x} ${sy}, ${c2x} ${ty}, ${tx} ${ty}`;
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
