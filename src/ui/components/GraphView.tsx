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

import { type EdgeValueLookup, lookupEdgeValue, lookupNodeValue } from "@/core/edge-value-lookup";
import { type ByteFormat, formatBytes } from "@/core/format";
import {
  type CipherGraph,
  type ContainerNode,
  type GraphEdge,
  type GraphNode,
  type GraphWarning,
  buildIterateFeedbackPredicate,
  collapseGraph,
  deriveAuxGraph,
  expandCollapsedIterates,
  replicateHighFanoutSources,
  validateGraph,
} from "@/core/graph";
import { inferShapesAtAnchors, validateShapes } from "@/core/spec-shapes";
import type { AuxValue, State, StepNode } from "@/core/types";
import { For, Show, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { useByteFormat } from "../stores/format";
import {
  setNodePosition,
  setReplicationMode,
  toggleCollapse,
  useLayoutMap,
} from "../stores/layout";
import { registry } from "../stores/registry";
import {
  duplicateRoundInSpec,
  insertStepIntoSpec,
  isRoundDuplicatable,
  removeStepFromSpec,
  useMode,
  useSpec,
} from "../stores/spec";
import { getTrace, setSelectedStepId, useFrameIndex, useTraceVersion } from "../stores/trace";
import {
  ALL_VIEW_DENSITIES,
  DENSITY_SCALE,
  VIEW_DENSITY_LABELS,
  type ViewDensity,
  setViewDensity,
  useViewDensity,
} from "../stores/view-density";
import {
  DEFAULT_REPLICATION_THRESHOLD,
  REPLICATION_THRESHOLD_MAX,
  REPLICATION_THRESHOLD_MIN,
  setReplicationEnabled,
  setReplicationPanelOpen,
  setReplicationThreshold,
  toggleReplicationPanelOpen,
  useReplicationEnabled,
  useReplicationPanelOpen,
  useReplicationThreshold,
} from "../stores/view-replication";
import {
  type ValueInspectorTarget,
  clearSelectedTarget,
  encodeEdgeKey,
  isEdgeSelected,
  isNodeSelected,
  toggleInspectorPanelOpen,
  toggleSelectedEdge,
  toggleSelectedNode,
  useInspectorPanelOpen,
  useSelectedTarget,
} from "../stores/view-value-inspector";
import {
  VIEW_ZOOM_DEFAULT,
  VIEW_ZOOM_MAX,
  VIEW_ZOOM_MIN,
  getViewZoom,
  resetViewZoom,
  setViewZoom,
  stepViewZoom,
  useViewZoom,
} from "../stores/view-zoom";
import { GraphHelpModal } from "./GraphHelpModal";
import { STEP_TYPE_DRAG_MIME, StepPalette, useActiveDragStepType } from "./StepPalette";

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
/**
 * Base (1.0×) horizontal step between adjacent replica rows above a shared
 * consumer.
 *
 * **2026-05-16 pivot to straight-line + offset-start-point + start-dot:**
 * stays at 0 so replicas remain in a clean vertical column. The visual
 * disambiguation between stacked replicas' arrows now comes from
 * `replicaSourceXOffset` (alternating-sign horizontal shift of the
 * arrow's START point on the replica's bottom edge) plus a small visible
 * dot at that start point — so even when an arrow visually crosses an
 * intervening replica box, the eye reads "this arrow starts from the dot
 * up here, not the box it passes through." The constant stays defined
 * (rather than removed) so the placement helpers and their tests keep
 * their shape.
 */
const BASE_REPLICA_ROW_X_STEP = 0;
/**
 * Base (1.0×) horizontal step applied to the SOURCE-side x of a replica
 * edge in the vertical regime. Row k's arrow emerges from x =
 * `replicaCenter.x + (row - (total-1)/2) × step` on the replica's
 * bottom edge — monotonic spread by row, MATCHING the direction of
 * `replicaTargetXOffset`'s spread at the consumer head so each
 * source's arrow stays on its own column side (row 0 left → left
 * port; row N-1 right → right port; no crossovers). 32 px ≈ ¼ ×
 * LEAF_W at normal density — wide enough for the start-dots to read
 * as visibly distinct, narrow enough that even a 5-source spread
 * (±64 px) stays inside LEAF_W/2 = 66 with the EdgePath clamp as a
 * backstop.
 */
const BASE_REPLICA_SOURCE_X_STEP = 32;
/**
 * Base (1.0×) vertical gap between the bottom of a row-0 replica and the
 * top of its consumer (the block-chip for an iterate consumer, or the
 * spine row for an aux-only root). Replaces STACK_GAP (= 6) at the
 * replica-lift sites — STACK_GAP is tuned for sibling stacking inside
 * groups (tight, ~6 px) but that turned out too tight for replicas: the
 * `ARROW_INSET` = 6 ate the entire shaft and the arrow rendered as just
 * an arrowhead kissing the chip's top edge. 20 px leaves a 14 px visible
 * arrow shaft (20 − ARROW_INSET = 14) — short enough to keep replicas
 * visually adjacent to their consumer, long enough that the arrow reads
 * as a directed line not a flush mark.
 */
const BASE_REPLICA_LIFT_GAP = 20;
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
  /**
   * Port-spreading polish (2026-05-16, follow-up to Slice 7c):
   * horizontal step between stacked replica rows above the same consumer.
   * Row 0 lives at `consumer.x`; row 1 at `consumer.x + REPLICA_ROW_X_STEP`;
   * row k at `consumer.x + k * REPLICA_ROW_X_STEP`. Gives upper-row arrows
   * a diagonal slope so they don't pass straight through intervening
   * replica boxes — Slice 7c's "same x column per source" invariant
   * weakened deliberately because the column overlap made multi-source
   * fan-IN arrows mostly invisible (SVG paint order: edges before nodes
   * = intervening replica fills obscured the line). Source A still
   * always at row 0 globally, so the eye still tracks "source X = row Y."
   *
   * Density-scaled from `BASE_REPLICA_ROW_X_STEP = 16` (= FLOW_GAP at
   * normal density — modest shift, keeps total horizontal spread bounded
   * for 3-4 stacked rows).
   */
  readonly REPLICA_ROW_X_STEP: number;
  /**
   * Straight-line + offset-start-point + start-dot per-row step
   * (2026-05-16). With `REPLICA_ROW_X_STEP === 0` replicas stack in
   * a clean vertical column; their outgoing arrows ORIGINATE from
   * offset x positions on the column's bottom edge so the eye reads
   * "row 0's arrow starts at the column's left; row N-1's starts at
   * the right." A visible start-dot pinned at each arrow's tail
   * reinforces the cue even when the straight line crosses an
   * intervening replica's box. `replicaSourceXOffset` uses the SAME
   * monotonic spread as the target-side port-spreading, so source
   * and target x match per row — every arrow stays in its own column
   * side without crossover. Density-scaled from
   * `BASE_REPLICA_SOURCE_X_STEP = 32`.
   */
  readonly REPLICA_SOURCE_X_STEP: number;
  /**
   * Vertical gap between row-0 replica and consumer. See
   * `BASE_REPLICA_LIFT_GAP` — wider than STACK_GAP (6) so the arrow
   * shaft has visible length after `ARROW_INSET` subtraction.
   */
  readonly REPLICA_LIFT_GAP: number;
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
    REPLICA_ROW_X_STEP: Math.round(BASE_REPLICA_ROW_X_STEP * scale),
    REPLICA_SOURCE_X_STEP: Math.round(BASE_REPLICA_SOURCE_X_STEP * scale),
    REPLICA_LIFT_GAP: Math.round(BASE_REPLICA_LIFT_GAP * scale),
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
 * Replica placement info, derived once at the top of `layoutRoot` from the
 * graph's nodes + aux edges and threaded down through `layoutNode`. Two
 * lookups the group-layout pass needs:
 *
 *   - `isReplica(id)` — is this child a fan-out replica? Replicas are
 *     skipped in the main vertical-stack pass so they don't displace
 *     real siblings (and don't sit between state-spine-consecutive
 *     leaves obscuring the spine edge).
 *   - `consumerOf(replicaId)` — where does this replica's short aux
 *     arrow terminate? The replica is positioned to the LEFT of the
 *     consumer at the consumer's y, after the consumer has been laid out
 *     in the main pass.
 *
 * Empty for graphs without replication on (the master-switch case);
 * `layoutNode`'s replica branch then short-circuits to current behavior.
 */
type ReplicaPlacement = {
  readonly isReplica: ReadonlySet<string>;
  readonly consumerOf: ReadonlyMap<string, string>;
  /**
   * Slice 7c: replica → originating source id (the `replicaOf` field on
   * the GraphNode, copied here for O(1) lookup during placement). Together
   * with `rowOfSource` this implements "by-source columns above each
   * consumer" — one source's replicas all share a row, multiple sources
   * stack vertically.
   */
  readonly sourceOf: ReadonlyMap<string, string>;
  /**
   * Slice 7c: source id → its globally-stable row index (0 = closest to
   * the spine, larger = farther up). Assigned in `graph.nodes` walk
   * order (which is itself a deterministic walk from `deriveAuxGraph`),
   * so source A is always row 0 and source B always row 1 across EVERY
   * consumer they touch — even consumers where A has no replica (those
   * consumers' row 0 sits empty; B still occupies row 1, never row 0).
   * This globally-stable property costs vertical space (a container with
   * only row-2 replicas gets 3 rows of lift, 2 empty) and pays in
   * scannability — the eye can track "source X always at this row."
   */
  readonly rowOfSource: ReadonlyMap<string, number>;
};

const EMPTY_REPLICA_PLACEMENT: ReplicaPlacement = {
  isReplica: new Set(),
  consumerOf: new Map(),
  sourceOf: new Map(),
  rowOfSource: new Map(),
};

/**
 * Position the row-k replica relative to its consumer's anchor x and top y.
 *
 * **Row 0** lands at `consumer.y − LEAF_H − REPLICA_LIFT_GAP`, at
 * `anchorX` (= consumer.x, or first-non-replica-body-child.x for
 * iterate consumers per Slice 2). `REPLICA_LIFT_GAP` (= 20 px)
 * replaced the original `STACK_GAP` (= 6 px) on 2026-05-16 so the
 * arrow shaft between the row-0 start-dot and the consumer arrowhead
 * has visible length after `ARROW_INSET` subtraction. Single-source
 * ciphers (every aux-only baseline today — AES key-expansion, Speck,
 * Serpent) have `rowOfSource[src] = 0` always, so they only ever hit
 * this row-0 case.
 *
 * **Rows k ≥ 1** stack diagonally up-and-right (2026-05-16 port-spreading
 * polish):
 *   - **y**: `baseY − k × (LEAF_H + FLOW_GAP)`. Uses FLOW_GAP (16) not
 *     STACK_GAP (6) between rows so 3+ stacked replicas have visible
 *     inter-row gaps and the arrows from upper rows have room to draw
 *     through those gaps.
 *   - **x**: `anchorX + k × REPLICA_ROW_X_STEP`. Each row shifts right
 *     so upper-row arrows have a diagonal slope to the consumer head —
 *     they no longer pass straight through the intervening replicas'
 *     bounding boxes (which would obscure them under SVG paint order).
 *
 * **Why this beat the original Slice 7c "same x column per source"
 * invariant:** the canonical bad case (AES-128 ECB + 3 always-overrides
 * + collapsed iterate = 3 stacked replicas above each block-chip) showed
 * the column-stacked arrows were mostly invisible — each arrow ran
 * straight down through the intervening replicas' fills. The diagonal
 * shift trades the "same x column" property for arrow visibility. Source
 * A still occupies row 0 globally, so the eye still tracks "row Y
 * always = source X" — only the x within a row varies by consumer.
 */
const replicaSlotPosition = (
  anchorX: number,
  consumerY: number,
  row: number,
  consts: LayoutConstants,
): { x: number; y: number } => {
  const baseY = consumerY - consts.LEAF_H - consts.REPLICA_LIFT_GAP;
  return {
    x: anchorX + row * consts.REPLICA_ROW_X_STEP,
    y: baseY - row * (consts.LEAF_H + consts.FLOW_GAP),
  };
};

/**
 * Vertical lift height a container needs to host `maxRow + 1` rows of
 * replicas above its first state-consumer body step (or above the
 * canvas's spine row, for root-level placements).
 *
 * Formula: row 0 takes `LEAF_H + STACK_GAP`, each row above adds
 * `LEAF_H + FLOW_GAP`. Returns 0 when `maxRow < 0` (no replicas).
 *
 * Single-row case (`maxRow === 0`) = `LEAF_H + STACK_GAP`, byte-identical
 * to pre-port-spreading. Multi-row case grows with FLOW_GAP per extra row,
 * matching `replicaSlotPosition`'s row-spacing.
 */
// Implementation note: row 0 uses REPLICA_LIFT_GAP (= 20) instead of
// STACK_GAP (= 6) — the wider gap leaves visible arrow-shaft room
// after ARROW_INSET. Matches `replicaSlotPosition`'s baseY formula.
const replicaLiftHeight = (maxRow: number, consts: LayoutConstants): number => {
  if (maxRow < 0) return 0;
  return consts.LEAF_H + consts.REPLICA_LIFT_GAP + maxRow * (consts.LEAF_H + consts.FLOW_GAP);
};

/**
 * Build the replica → consumer + replica → source + source → row maps
 * from the graph. The replica's outgoing edge points at its consumer
 * (every replica has exactly one — that's the point of replication).
 * Using the edge list (not the `${src}@->${consumer}` id format) keeps
 * the layout decoupled from `graph.ts`'s replica-id convention.
 *
 * **Invariant** (Slice 7c): the zone above each consumer hosts ONLY
 * replicas. Non-replicated aux sources route via long edges from their
 * canvas position, regardless of which consumer they target — they
 * never enter the lift row. Future work that wants "above-consumer"
 * placement for a non-replica source must promote it to a replica first
 * (which is what `replicateHighFanoutSources` already does for the
 * always-overrides path).
 *
 * **Kind-agnostic** (Slice 7c, 7b prep): `consumerOf` walks edges
 * regardless of kind, so a future state-kind replica (Slice 7b drops
 * the `kind === "aux"` filter in `replicateHighFanoutSources`) lands
 * here identically to today's aux-kind replicas. Today every replica
 * has exactly one outgoing edge by construction (`replicateHighFanoutSources`
 * produces one replica per `(src, consumer)` pair with a single rewritten
 * edge), so `consumerOf.set(e.from, e.to)` never fights itself.
 */
const buildReplicaPlacement = (graph: CipherGraph): ReplicaPlacement => {
  const isReplica = new Set<string>();
  const sourceOf = new Map<string, string>();
  const rowOfSource = new Map<string, number>();
  // Single deterministic walk: encounter order over graph.nodes is the
  // order deriveAuxGraph emitted (spec-walk order). Each new source id
  // claims the next row index — first source seen → row 0.
  for (const n of graph.nodes) {
    if (n.replicaOf === undefined) continue;
    isReplica.add(n.stepId);
    sourceOf.set(n.stepId, n.replicaOf);
    if (!rowOfSource.has(n.replicaOf)) {
      rowOfSource.set(n.replicaOf, rowOfSource.size);
    }
  }
  if (isReplica.size === 0) return EMPTY_REPLICA_PLACEMENT;
  const consumerOf = new Map<string, string>();
  for (const e of graph.edges) {
    if (isReplica.has(e.from)) consumerOf.set(e.from, e.to);
  }
  return { isReplica, consumerOf, sourceOf, rowOfSource };
};

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
  replicas: ReplicaPlacement,
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
    //
    // Replica placement uses a DUAL strategy because there are two distinct
    // scenarios that would cause the replica to obscure an arrow:
    //
    //   1. **Consumer is NOT the first non-replica child** (AES case:
    //      `add-round-key` is the LAST step). The intra-column state
    //      spine arrow `mix-columns → add-round-key` runs vertically
    //      through the column. A replica in the column blocks it. The
    //      inter-round spine arrow `prev.add-round-key → curr.sub-bytes`
    //      enters at `sub-bytes`'s y (the FIRST child) — far from the
    //      replica's consumer y. → LEFT GUTTER at consumer.y is safe.
    //
    //   2. **Consumer IS the first non-replica child** (Serpent case:
    //      `add-round-key` is the FIRST step). The inter-round spine
    //      arrow `prev.linear-transform → curr.add-round-key` enters
    //      from the LEFT at the first child's y. A replica in the LEFT
    //      gutter at that y would obscure that arrow. There's no in-
    //      column child above the consumer to displace, so the safe
    //      placement is to LIFT the column by `LEAF_H + STACK_GAP` and
    //      place the replica in the new space ABOVE the consumer at
    //      the column's x. The incoming arrow now enters BELOW the
    //      replica's y-range, passing cleanly.
    //
    // Both strategies are independent: gutter widens the group when any
    // non-first-child replica is present; lift heightens the group when
    // any first-child replica is present. A hypothetical mixed group
    // (some replicas first-child, others not) gets BOTH treatments.
    const normalChildren: string[] = [];
    for (const childId of container.childIds) {
      if (!replicas.isReplica.has(childId)) normalChildren.push(childId);
    }
    const firstNormalId = normalChildren[0];

    const leftGutterReplicas: string[] = [];
    const liftedReplicas: string[] = [];
    for (const childId of container.childIds) {
      if (!replicas.isReplica.has(childId)) continue;
      const consumerId = replicas.consumerOf.get(childId);
      if (consumerId === undefined) continue;
      if (consumerId === firstNormalId) {
        liftedReplicas.push(childId);
      } else {
        leftGutterReplicas.push(childId);
      }
    }

    const gutterW = leftGutterReplicas.length > 0 ? consts.LEAF_W + consts.FLOW_GAP : 0;
    // Slice 7c + port-spreading polish (2026-05-16): lift height grows
    // with the maximum source-row used by any lifted replica in this
    // group. Single-source case (all replicas at row 0) → maxLiftRow = 0
    // → liftH = LEAF_H + REPLICA_LIFT_GAP (= 48 px at normal density,
    // up from LEAF_H + STACK_GAP = 34 px before 2026-05-16 — the wider
    // gap gives the arrow shaft visible length after ARROW_INSET).
    // Multi-row case uses `replicaLiftHeight`, which spaces rows by
    // FLOW_GAP (matching `replicaSlotPosition`'s y formula). Computed
    // BEFORE the third pass needs it because innerY (the in-column
    // children's
    // start) depends on liftH.
    let maxLiftRow = -1;
    for (const rId of liftedReplicas) {
      const sId = replicas.sourceOf.get(rId);
      if (sId === undefined) continue;
      const row = replicas.rowOfSource.get(sId) ?? 0;
      if (row > maxLiftRow) maxLiftRow = row;
    }
    const liftH = replicaLiftHeight(maxLiftRow, consts);

    const innerX = startX + consts.CONTAINER_PAD + gutterW;
    let innerY = startY + HEADER_H + consts.CONTAINER_PAD + liftH;
    let maxChildW = 0;
    let lastChildBottom = innerY;
    for (const childId of normalChildren) {
      const childBox = layoutNode(
        childId,
        innerX,
        innerY,
        containersById,
        pinned,
        out,
        consts,
        replicas,
      );
      innerY = childBox.y + childBox.h + consts.STACK_GAP;
      lastChildBottom = childBox.y + childBox.h;
      if (childBox.w > maxChildW) maxChildW = childBox.w;
    }

    // Second pass: place LEFT-gutter replicas (consumers that are NOT
    // the first child) at their consumer's vertical center.
    const replicaX = startX + consts.CONTAINER_PAD;
    for (const replicaId of leftGutterReplicas) {
      const consumerId = replicas.consumerOf.get(replicaId);
      if (consumerId === undefined) continue;
      const consumerBox = out.get(consumerId);
      if (!consumerBox) continue;
      const replicaY = consumerBox.y + (consumerBox.h - consts.LEAF_H) / 2;
      out.set(replicaId, { x: replicaX, y: replicaY, w: consts.LEAF_W, h: consts.LEAF_H });
    }

    // Third pass: place LIFTED replicas (consumers that ARE the first
    // child) above their consumer in the column. The liftH shift on
    // innerY above guarantees row 0's y lands inside the group's padded
    // inner area, just below the header.
    //
    // Slice 7c + port-spreading polish (2026-05-16): each replica's slot
    // is `replicaSlotPosition(anchorX, anchorY, row, consts)` — y is
    // determined by the source's GLOBAL row (source A at row 0 closest
    // to consumer, source B at row 1 above, etc.) and x shifts right by
    // `REPLICA_ROW_X_STEP` per row so upper rows take a diagonal slope
    // that bypasses intervening replica boxes. See `replicaSlotPosition`
    // for the rationale on dropping Slice 7c's "same x column per
    // source" invariant.
    let maxLiftReplicaRight = 0;
    for (const replicaId of liftedReplicas) {
      const consumerId = replicas.consumerOf.get(replicaId);
      if (consumerId === undefined) continue;
      const consumerBox = out.get(consumerId);
      if (!consumerBox) continue;
      const sId = replicas.sourceOf.get(replicaId);
      const row = sId !== undefined ? (replicas.rowOfSource.get(sId) ?? 0) : 0;
      const slot = replicaSlotPosition(consumerBox.x, consumerBox.y, row, consts);
      out.set(replicaId, {
        x: slot.x,
        y: slot.y,
        w: consts.LEAF_W,
        h: consts.LEAF_H,
      });
      const replicaRight = slot.x + consts.LEAF_W;
      if (replicaRight > maxLiftReplicaRight) maxLiftReplicaRight = replicaRight;
    }

    // Grow the column to fit upper-row replicas that shifted right past
    // the consumer's natural width. The diagonal stack extends rightward
    // by `maxLiftRow * REPLICA_ROW_X_STEP`; the group's box has to
    // contain it so the row-N replica doesn't visually leak past the
    // group's right edge. innerX is `startX + CONTAINER_PAD + gutterW`,
    // so the rightmost replica is at `maxLiftReplicaRight - innerX`
    // pixels into the column from the column's left edge — that's our
    // floor for `columnW`.
    const innerXForCol = startX + consts.CONTAINER_PAD + gutterW;
    const liftReplicaColumnW = maxLiftReplicaRight > 0 ? maxLiftReplicaRight - innerXForCol : 0;
    const columnW = Math.max(maxChildW, consts.LEAF_W, liftReplicaColumnW);
    const w = gutterW + columnW + 2 * consts.CONTAINER_PAD;
    // Height formula uses lastChildBottom which already includes the
    // liftH shift via innerY; don't add liftH again.
    const h = lastChildBottom - startY + consts.CONTAINER_PAD;
    const box: Box = { x: startX, y: startY, w, h };
    out.set(id, box);
    return box;
  }

  // Iterate: horizontal flow of children. Replica placement is the
  // horizontal-flow MIRROR of the group's vertical-flow gutter: replicas
  // go ABOVE their consumer (orthogonal to the spine direction at this
  // scope) so a state-spine arrow running along the body row (e.g.
  // initial.add-round-key → round.1.sub-bytes in AES-128-ECB's iterate
  // body) doesn't pass through a replica sitting at the same y. The body
  // row shifts down by LEAF_H + STACK_GAP only when at least one replica
  // is present so non-replicated bodies keep their original height.
  const hasIterateReplicas = container.childIds.some((cId) => replicas.isReplica.has(cId));
  // Slice 7c + port-spreading polish (2026-05-16): iterate-body replica
  // lift scales with the maximum source-row used by any in-body replica.
  // Single-source case (rowOfSource === 0 everywhere) → liftH = LEAF_H +
  // REPLICA_LIFT_GAP. (`REPLICA_LIFT_GAP` replaced the original
  // `STACK_GAP` on 2026-05-16 so the row-0 → consumer arrow shaft
  // doesn't collapse to zero length after `ARROW_INSET` subtraction —
  // user-observed bug on the canonical AES-128 ECB collapsed-iterate
  // case.) Multi-row case uses `replicaLiftHeight`, which spaces rows
  // by FLOW_GAP (matching `replicaSlotPosition`'s y formula). Globally
  // stable: source A always at row 0 regardless of which body chip
  // each replica targets.
  let iterateMaxRow = -1;
  for (const childId of container.childIds) {
    if (!replicas.isReplica.has(childId)) continue;
    const sId = replicas.sourceOf.get(childId);
    if (sId === undefined) continue;
    const row = replicas.rowOfSource.get(sId) ?? 0;
    if (row > iterateMaxRow) iterateMaxRow = row;
  }
  const replicaLiftH = hasIterateReplicas ? replicaLiftHeight(iterateMaxRow, consts) : 0;

  let innerX = startX + consts.CONTAINER_PAD;
  const innerY = startY + HEADER_H + consts.CONTAINER_PAD + replicaLiftH;
  let maxChildH = 0;
  let lastChildRight = innerX;
  for (const childId of container.childIds) {
    if (replicas.isReplica.has(childId)) continue;
    const childBox = layoutNode(
      childId,
      innerX,
      innerY,
      containersById,
      pinned,
      out,
      consts,
      replicas,
    );
    innerX = childBox.x + childBox.w + consts.FLOW_GAP;
    lastChildRight = childBox.x + childBox.w;
    if (childBox.h > maxChildH) maxChildH = childBox.h;
  }

  // Second pass: place iterate-body replicas above their consumers. The
  // lifted innerY guarantees row 0's y lands at the OLD innerY (the
  // natural top of the inner content), inside the container's box.
  //
  // Slice 7c + port-spreading polish (2026-05-16): each replica's slot
  // comes from `replicaSlotPosition`. y stacks by source row (globally
  // stable — source A always at row 0); x shifts right by
  // `REPLICA_ROW_X_STEP` per row so upper-row arrows have a diagonal
  // slope. See `replicaSlotPosition` for full rationale.
  let maxIterateReplicaRight = 0;
  for (const childId of container.childIds) {
    if (!replicas.isReplica.has(childId)) continue;
    const consumerId = replicas.consumerOf.get(childId);
    if (consumerId === undefined) continue;
    const consumerBox = out.get(consumerId);
    if (!consumerBox) continue;
    const sId = replicas.sourceOf.get(childId);
    const row = sId !== undefined ? (replicas.rowOfSource.get(sId) ?? 0) : 0;
    const slot = replicaSlotPosition(consumerBox.x, consumerBox.y, row, consts);
    out.set(childId, {
      x: slot.x,
      y: slot.y,
      w: consts.LEAF_W,
      h: consts.LEAF_H,
    });
    const replicaRight = slot.x + consts.LEAF_W;
    if (replicaRight > maxIterateReplicaRight) maxIterateReplicaRight = replicaRight;
  }

  // Grow the iterate container to fit upper-row replicas that shifted
  // right past `lastChildRight`. A row-N replica above the last body
  // child extends to `lastChildBox.x + N * REPLICA_ROW_X_STEP + LEAF_W`;
  // the iterate's box must contain it.
  const effectiveLastRight = Math.max(lastChildRight, maxIterateReplicaRight);
  const w = effectiveLastRight - startX + consts.CONTAINER_PAD;
  const h = HEADER_H + 2 * consts.CONTAINER_PAD + replicaLiftH + maxChildH;
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
  /**
   * Root-level leaves whose registered `shapeContract.input` is `"any"`
   * (i.e. they don't consume cipher state — `aes.key-expansion@1`,
   * `generic.iv-load@1`, etc.). They get lifted to the same `CANVAS_MARGIN`
   * row that root replicas live on, mirroring the existing "spine row is
   * for state flow, ancillary computation sits above" visual language.
   * Without this lift, the synthetic plaintext-pill → first-state-consumer
   * arrow geometrically passes through `key-expansion`'s rectangle on
   * AES specs — visually confusing even though the arrow doesn't route
   * through that node logically.
   *
   * Defaults to an empty set so callers that haven't computed it (the
   * test suite drives `layoutRoot` directly with the old signature)
   * keep the same layout they always had.
   */
  auxOnlyRootIds: ReadonlySet<string> = new Set(),
): { boxes: Map<string, Box>; canvasW: number; canvasH: number } => {
  const containersById = new Map<string, ContainerNode>();
  for (const c of graph.containers) containersById.set(c.id, c);

  // Derive replica placement info once. When replication is off (the
  // master switch in GraphView), the set is empty and the group-layout
  // pass short-circuits to the original column-only behavior.
  const replicas = buildReplicaPlacement(graph);

  // Root is also horizontal flow, so the same orthogonal-axis principle
  // as the iterate body applies: a root-level replica spliced between
  // state-spine-consecutive leaves (e.g. AES-128 `key-expansion` →
  // `key-expansion@->initial.add-round-key` → `initial.add-round-key`)
  // would sit at the same y as the spine arrow and obscure it. Shift the
  // entire row down by LEAF_H + STACK_GAP and place root replicas ABOVE
  // their consumer at the OLD CANVAS_MARGIN row.
  //
  // Two reasons we shift: a root replica is present, OR an aux-only
  // root leaf is present (post-Slice 1 endpoint pills — see above).
  // Shifting once when either condition fires keeps the geometry simple
  // and means the aux-only-lift row and the replica row coincide
  // visually, reinforcing "above the spine = supporting computation."
  //
  // Slice 7c: root-replica lift now scales with the maximum source-row
  // used by any root replica. Aux-only-roots still want exactly 1 row
  // of lift (they sit at CANVAS_MARGIN regardless of replica row count
  // — the topmost lifted row). When BOTH conditions fire, the lift
  // takes the larger of the two needs.
  let rootReplicaMaxRow = -1;
  for (const id of graph.rootIds) {
    if (!replicas.isReplica.has(id)) continue;
    const sId = replicas.sourceOf.get(id);
    if (sId === undefined) continue;
    const row = replicas.rowOfSource.get(sId) ?? 0;
    if (row > rootReplicaMaxRow) rootReplicaMaxRow = row;
  }
  // Port-spreading polish (2026-05-16): replica lift uses
  // `replicaLiftHeight` (FLOW_GAP between rows); aux-only-roots only
  // need one row of lift (LEAF_H + REPLICA_LIFT_GAP — same gap the
  // replica path uses, so the arrow shaft is visible). Take the
  // larger of the two so a graph with both — replicas at row 0+ AND
  // aux-only roots present — still has room for both pictures.
  const replicaLiftHRoot = replicaLiftHeight(rootReplicaMaxRow, consts);
  const hasAuxOnlyRoots = graph.rootIds.some((id) => auxOnlyRootIds.has(id));
  const auxOnlyLiftH = hasAuxOnlyRoots ? consts.LEAF_H + consts.REPLICA_LIFT_GAP : 0;
  const rootReplicaLiftH = Math.max(replicaLiftHRoot, auxOnlyLiftH);
  const rowStartY = CANVAS_MARGIN + rootReplicaLiftH;

  const boxes = new Map<string, Box>();
  let cursorX = CANVAS_MARGIN;
  let maxRight = CANVAS_MARGIN;
  let maxBottom = CANVAS_MARGIN;
  for (const id of graph.rootIds) {
    if (replicas.isReplica.has(id)) continue;
    // Capture the cursor BEFORE layoutNode — that's the natural-flow X
    // for this root entity, used for cursor advancement even when the
    // entity is pinned somewhere else. box.w is content-derived (depends
    // on children, not on this entity's pin), so it's safe to use as the
    // natural width for the advancement step.
    const naturalX = cursorX;
    // Aux-only root leaves lay out at the lifted row (CANVAS_MARGIN), the
    // rest at the spine row (rowStartY). `layoutNode` honors pins
    // internally, so a user who manually drags an aux-only leaf to the
    // spine row keeps that pin.
    const startY = auxOnlyRootIds.has(id) ? CANVAS_MARGIN : rowStartY;
    const box = layoutNode(id, cursorX, startY, containersById, pinned, boxes, consts, replicas);
    cursorX = naturalX + box.w + consts.FLOW_GAP;
    const right = box.x + box.w;
    const bottom = box.y + box.h;
    if (right > maxRight) maxRight = right;
    if (bottom > maxBottom) maxBottom = bottom;
  }

  // Second pass: place root-level replicas above their consumers. The
  // shift above guarantees the bottom replica row (row 0) sits at
  // `CANVAS_MARGIN + (totalLiftRows - 1) * (LEAF_H + STACK_GAP)` for
  // non-pinned consumers, with higher rows stacking up to CANVAS_MARGIN.
  //
  // Slice 7c: by-source columns. Multiple distinct sources targeting
  // the same consumer (e.g. setting both `compute-block-count` and
  // `split-blocks` to "always" in the replication-overrides panel yields
  // two replicas pointing at the iterate) used to tile rightward via a
  // per-consumer x-step counter; post-7c they stack VERTICALLY at the
  // consumer's anchor x (or first-body-child x for iterate consumers,
  // per Slice 2). Source A's replicas all share row 0, source B all
  // share row 1, etc. — globally stable across every consumer they
  // touch. The same pattern lives in `layoutNode`'s group + iterate
  // branches; one global `rowOfSource` map drives all three sites.
  for (const id of graph.rootIds) {
    if (!replicas.isReplica.has(id)) continue;
    const consumerId = replicas.consumerOf.get(id);
    if (consumerId === undefined) continue;
    const consumerBox = boxes.get(consumerId);
    if (!consumerBox) continue;
    const sId = replicas.sourceOf.get(id);
    const row = sId !== undefined ? (replicas.rowOfSource.get(sId) ?? 0) : 0;
    // Slice-2 anchor: when the consumer is an iterate container, place
    // the replica above the iterate body's first NON-REPLICA child —
    // i.e. the first actual body step — instead of the iterate's own
    // left edge. The arrow then drops "into the start of the body
    // where the aux is read," matching the runtime: the iterate
    // consumes `countFromAux` / `blocksFromAux` at iteration entry,
    // and the first body step is the first observer of the resulting
    // state. We skip past replicas in `childIds` because
    // `replicateHighFanoutSources` splices in-body replicas (e.g.
    // `key-expansion@->initial.add-round-key`) AHEAD of the real
    // first step. Anchoring above the replica chip instead would
    // visually point the count-arrow at a key-expansion replica —
    // misleading. The non-replica lookup picks the real consumer.
    // Collapsed iterates have `childIds === []` so the lookup falls
    // back to the consumer's own x — no special-case branch needed.
    //
    // Generality gap noted for future work: this special-case lives
    // only here in `layoutRoot`'s second pass. The two sibling replica-
    // placement loops (`layoutNode`'s group branch + iterate-body
    // branch) DON'T have the iterate-target check. A hypothetical
    // future cipher where a replica sits inside a group but targets
    // an iterate would have its source anchored at the iterate's left
    // edge here. The target-side `visualEdgeTargetId` retarget still
    // applies, so the arrow lands correctly; only the source's x is
    // less pedagogically meaningful. No shipped or planned cipher
    // hits this — defer until something demands it.
    const consumerContainer = containersById.get(consumerId);
    const firstNonReplicaChildId =
      consumerContainer?.kind === "iterate"
        ? consumerContainer.childIds.find((cid) => !replicas.isReplica.has(cid))
        : undefined;
    const firstChildBox =
      firstNonReplicaChildId !== undefined ? boxes.get(firstNonReplicaChildId) : undefined;
    const anchorX = firstChildBox?.x ?? consumerBox.x;
    // Port-spreading polish: x/y come from `replicaSlotPosition`, which
    // applies the row-shift and FLOW_GAP row-spacing uniformly across
    // the three placement sites.
    const slot = replicaSlotPosition(anchorX, consumerBox.y, row, consts);
    boxes.set(id, {
      x: slot.x,
      y: slot.y,
      w: consts.LEAF_W,
      h: consts.LEAF_H,
    });
    // Replica boxes can now extend right past the consumer's x-range
    // (row k shifts by k × REPLICA_ROW_X_STEP); track that against
    // canvas extent so the SVG width grows to fit.
    const replicaRight = slot.x + consts.LEAF_W;
    if (replicaRight > maxRight) maxRight = replicaRight;
  }

  return {
    boxes,
    canvasW: maxRight + CANVAS_MARGIN,
    canvasH: maxBottom + CANVAS_MARGIN,
  };
};

/** Re-exported for tests that want to drive `layoutRoot` directly. */
export { layoutConstantsFor };

/**
 * Slice-2 follow-up: choose the visual target node for an edge.
 *
 * For replica→iterate-container aux edges, the arrow's arrowhead is
 * better anchored at the iterate body's FIRST child than at the iterate
 * container itself. Reason: the aux (`countFromAux` / `blocksFromAux`)
 * is data-model-consumed by the iterate at iteration entry — that's
 * what `edge.to` correctly says — but the runtime's first observer is
 * the first body step. Pointing the arrowhead there makes the visual
 * read "this aux flows INTO the start of the body," which matches the
 * runtime and shortens the visible sweep to zero when first-child is
 * a leaf (composes with Slice 2's source-side anchor at the same
 * `firstChild.x`).
 *
 * Edge `to` itself stays semantically correct — `validateGraph` and
 * the value inspector both read `edge.to` to surface
 * "this aux is consumed by ecb-blocks." Only the rendered arrow's
 * visual endpoint differs.
 *
 * When the first child is itself a wide group (no shipped cipher does
 * this today — AES's iterate body opens with the leaf
 * `initial.add-round-key`, and CBC follows the same shape), the arrow
 * lands at the group's top-center, not its left edge. Still
 * pedagogically correct — the wide thing IS the first consumer.
 *
 * Collapsed iterates (`childIds === []` — `collapseGraph` clears them)
 * fall back to the container's own box, preserving pre-retarget visual
 * behavior for that case.
 *
 * Why no `edge.kind === "aux"` filter: replicas only carry aux edges
 * (the state spine is sacred per the graph-narrative plan's Slice 7
 * design vote). A redundant filter would invite the reader to ask
 * "what about state replicas?" when none exist by construction.
 *
 * Cipher-family generality (advisor pass 2026-05-15):
 * - Single-block AES / Speck / Serpent: no iterates → early-return on
 *   the `kind === "iterate"` check, behavior unchanged.
 * - AES-128 ECB (and the upcoming CBC / CTR which reuse the same
 *   iterate primitive): primary use case; arrow is perfectly vertical.
 * - Feistel (near-future per `[[project-feistel-near-future]]`): the
 *   iterate primitive is independent of state branching, so any new
 *   state-edge kinds the Feistel data model introduces still flow
 *   into the iterate the same structural way. Helper unaffected.
 * - Hash functions (SHA-2 / SHA-3 / MAC / KDF per
 *   `[[project-hash-future]]`): if a hash spec uses `iterate` for
 *   block compression (likely), block-count and message-block aux
 *   replicas point at the iterate the same way ECB's count does.
 *   Same retarget applies. AEAD's two-output shape may force
 *   endpoint-pill (Slice 1) revision but is orthogonal to this code.
 *
 * Two cases this helper intentionally does NOT handle (future work
 * if a cipher demands them):
 * 1. **Nested iterates** (iterate-within-iterate): if the iterate's
 *    first non-replica child is ITSELF an iterate, the arrow lands
 *    on the inner iterate's box rather than its first body step.
 *    Recursion would fix this. Today no shipped or planned cipher
 *    nests iterates — CBC, CTR, and the planned hash compression
 *    loops are all flat.
 * 2. **Replica → group edges**: groups are pure visual wrappers
 *    without iteration-entry semantics, so the safe default is to
 *    anchor on the group's center (no retarget). If a future cipher
 *    routinely produces replica→group edges, revisit then.
 */
export const visualEdgeTargetId = (
  edge: GraphEdge,
  nodesById: ReadonlyMap<string, GraphNode>,
  containersById: ReadonlyMap<string, ContainerNode>,
): string => {
  const fromNode = nodesById.get(edge.from);
  if (fromNode?.replicaOf === undefined) return edge.to;
  const toContainer = containersById.get(edge.to);
  if (toContainer?.kind !== "iterate") return edge.to;
  // Skip past any replicas that were spliced into the body before the
  // actual first step (e.g. `replicateHighFanoutSources` puts
  // `key-expansion@->initial.add-round-key` AHEAD of
  // `initial.add-round-key` in the iterate body's `childIds`). We want
  // the visual edge to terminate at the real first consumer step, not
  // at another replica chip — otherwise the arrow appears to feed into
  // a key-expansion replica when it's actually the block-count flowing.
  const firstNonReplicaChildId = toContainer.childIds.find(
    (cid) => nodesById.get(cid)?.replicaOf === undefined,
  );
  return firstNonReplicaChildId ?? edge.to;
};

/**
 * Port-spreading follow-up to Slice 7c (2026-05-16, bumped above Slice 7b
 * after the 7c manual smoke pass surfaced fan-IN ambiguity at the chip head).
 *
 * Slice 7c stacks replicas vertically by globally-stable source rows —
 * scannability at the source side. But every replica's outgoing arrow lands
 * at the SAME point on the consumer's top edge, so 3+ stacked replicas
 * produce a fan-IN funnel where the arrows visually overlap at the
 * convergence point and the 12 px hit zones collapse onto each other near
 * the consumer head. Mid-arrow clicks still distinguish edges (the 12 px
 * `.graph-edge-hit` stroke runs the full path), but the convergence is
 * pedagogically muddy.
 *
 * Cure: spread the consumer-side attach x by the source's globally-stable
 * row, mirroring 7c's y-row philosophy. Source A's row-0 replica → fixed
 * x-offset on the consumer top across the entire canvas; source B's row-1
 * replica → next offset over; etc. Centered around the consumer's top-edge
 * midpoint via `(row - (total - 1) / 2) * portGap` so the spread is balanced
 * and degenerate (`total === 1`) → offset = 0 (no shift, no surprise on
 * single-source ciphers like every aux-only baseline today).
 *
 * **Why global rows, not per-consumer fan-in count:** matches the Slice 7c
 * y-stacking philosophy. A consumer that hosts only source B's replica
 * still puts B's arrow at the row-1 x-offset, leaving the row-0 column
 * empty on that consumer's top. Costs a constant per-source x-shift even
 * for single-replica consumers; pays in cross-canvas eye-tracking —
 * "source X always lands HERE on every consumer it touches."
 *
 * **Source side untouched** — replicas stay column-stacked at `consumer.x`
 * per Slice 7c. Only the target-end attach x shifts. The resulting slope
 * (from the replica's center bottom to a shifted point on the consumer's
 * top) is informative: it visually disambiguates which row the arrow came
 * from even before the eye traces the full path.
 *
 * **Kind-agnostic by construction** — keys off `replicaOf !== undefined`
 * via `replicas.sourceOf` (which only has entries for replica nodes), never
 * off `edge.kind`. Slice 7b will drop the `kind === "aux"` filter in
 * `replicateHighFanoutSources` and produce state-kind replicas; they get
 * the same offset machinery without changes here.
 *
 * **Returns 0 when**:
 *   - `edge.from` is not a replica (regular long-range aux or state edge —
 *     no row, no spread).
 *   - `total === 1` (single-source graph — no fan-in to disambiguate).
 *
 * @param edge — the edge being rendered (only `edge.from` is read).
 * @param replicas — the `ReplicaPlacement` map produced by
 *   `buildReplicaPlacement(graph)`; needs the same shape, so callers can
 *   call `buildReplicaPlacement` separately at the render site instead of
 *   threading it through the layout return.
 * @param portGap — density-scaled gap between adjacent rows' attach points.
 *   The render site computes `Math.max(6, round(LEAF_W / 10))` so the spread
 *   tracks the consumer width.
 *
 * The parameter shape `{ sourceOf, rowOfSource }` is intentionally
 * structural (not a `ReplicaPlacement` literal): the tests construct
 * placements via `buildReplicaPlacement` on synthetic graphs, but the
 * helper itself only needs the two maps. Keeping the type narrow lets a
 * future caller pass a hand-rolled `{ sourceOf, rowOfSource }` (e.g. an
 * isolated unit test exercising a corner of the formula) without having
 * to invent the full `ReplicaPlacement` interface. Don't widen this back
 * to `ReplicaPlacement` — the decoupling pays in test ergonomics.
 */
export const replicaTargetXOffset = (
  edge: GraphEdge,
  replicas: {
    readonly sourceOf: ReadonlyMap<string, string>;
    readonly rowOfSource: ReadonlyMap<string, number>;
  },
  portGap: number,
): number => {
  const sId = replicas.sourceOf.get(edge.from);
  if (sId === undefined) return 0;
  const row = replicas.rowOfSource.get(sId);
  if (row === undefined) return 0;
  const total = replicas.rowOfSource.size;
  if (total <= 1) return 0;
  return (row - (total - 1) / 2) * portGap;
};

/**
 * Horizontal shift applied to the SOURCE x of a replica edge's path in
 * the vertical regime. Returns a signed pixel offset; `EdgePath` adds
 * it to the source attach x (`sx`), so the arrow emerges from a
 * non-centred point on the replica's bottom edge.
 *
 * **Geometry** (2026-05-16 straight-line + offset-start-point approach):
 * uses the SAME monotonic spread formula as `replicaTargetXOffset` —
 * `(row - (total-1)/2) * step` — so source x and target x sweep in the
 * same direction by row. Row 0's source lands LEFT (same as its
 * target's left port), row N-1's source lands RIGHT (same as its
 * target's right port). Result: every arrow is a roughly parallel
 * down-and-slightly-inward line, no crossovers.
 *
 * **Why monotonic, not alternating:** an earlier draft alternated
 * `+1, −1, +2, −2, …` so each row claimed a different side of the
 * column. Visually clean for distinguishing rows in isolation, BUT
 * since the target-side `replicaTargetXOffset` is monotonic, the two
 * spreads sweep different directions per row — row 0 source-centre +
 * target-left = down-left; row 1 source-right + target-centre =
 * down-left; row 2 source-left + target-right = down-right → row 0's
 * arrow crosses row 2's. User observed this directly on the canonical
 * AES-128 ECB + 3-source case: "the arrow from key-expansion does an
 * unnecessary crossover the other arrows coming from above."
 *
 * **Single-source case** (total ≤ 1): returns 0. Today's AES /
 * Speck / Serpent key-expansion fan-outs all hit this branch — byte-
 * identical to pre-offset rendering, so the simple case stays clean.
 *
 * **Magnitude rationale:** LEAF_W = 132 ⇒ half-width = 66. `step = 32`
 * means a 3-source spread covers [-32, 0, +32] (total 64 px) — clearly
 * distinguishable dots without crowding the box edges. A 5-source
 * spread would reach ±64, just inside the half-width; EdgePath clamps
 * to LEAF_W/2 − 4 = 62 as a guard for any worse pathological case.
 *
 * Param shape is structural (not `ReplicaPlacement`) for the same
 * test-ergonomics reason as `replicaTargetXOffset`.
 */
export const replicaSourceXOffset = (
  edge: GraphEdge,
  replicas: {
    readonly sourceOf: ReadonlyMap<string, string>;
    readonly rowOfSource: ReadonlyMap<string, number>;
  },
  step: number,
): number => {
  const sId = replicas.sourceOf.get(edge.from);
  if (sId === undefined) return 0;
  const row = replicas.rowOfSource.get(sId);
  if (row === undefined) return 0;
  const total = replicas.rowOfSource.size;
  if (total <= 1) return 0;
  return (row - (total - 1) / 2) * step;
};

/**
 * Predicate: is this edge a replica edge — i.e., does it originate from
 * a fan-out replica node? Used to gate the straight-line path variant
 * and the start-dot rendering inside `EdgePath`. Non-replica edges keep
 * the curved cubic Bezier path that everything else in the canvas uses.
 */
export const isReplicaEdge = (
  edge: GraphEdge,
  replicas: { readonly isReplica: ReadonlySet<string> },
): boolean => replicas.isReplica.has(edge.from);

/**
 * Re-exported for tests that want to drive port-spreading directly.
 * `replicaTargetXOffset` reads only `sourceOf` + `rowOfSource` off the
 * placement, so tests can either call this builder or pass a hand-rolled
 * `{ sourceOf, rowOfSource }` literal.
 */
export { buildReplicaPlacement };

// ─── Component ─────────────────────────────────────────────────────────────

export const GraphView = () => {
  const spec = useSpec();
  const version = useTraceVersion();
  const layoutMap = useLayoutMap();
  const density = useViewDensity();
  const replicate = useReplicationEnabled();
  const replicationThreshold = useReplicationThreshold();
  // `useReplicationPanelOpen` follows the same accessor-factory shape as
  // its siblings above — call it ONCE here to capture the live accessor,
  // then read `replicationPanelOpen()` (not `useReplicationPanelOpen()`)
  // wherever we need the current boolean. Calling the factory inline in
  // JSX would always return a truthy function reference and the panel
  // would never close.
  const replicationPanelOpen = useReplicationPanelOpen();
  // Value inspector. Same accessor-factory pattern as
  // `replicationPanelOpen` above: capture each accessor ONCE so the
  // reactive call sites below read the live boolean instead of a
  // truthy function reference. Click-only — no hover signal.
  const selectedTarget = useSelectedTarget();
  const inspectorPanelOpen = useInspectorPanelOpen();
  const frameIndex = useFrameIndex();
  const byteFormat = useByteFormat();
  // Clear the selection whenever the user swaps to a different cipher spec.
  // A selected target from a prior spec points at ids that no longer
  // exist in the new graph; without this reset the panel would render
  // "missing" against stale identity (see `view-value-inspector.ts`
  // module docstring).
  createEffect(
    on(
      () => spec().id,
      () => clearSelectedTarget(),
      { defer: true },
    ),
  );

  /**
   * Per-spec zoom factor for the SVG canvas (Slice 3 of the
   * graph-narrative-and-zoom plan). Applied by scaling the SVG's rendered
   * `width`/`height` while keeping `viewBox` fixed at the logical canvas
   * dimensions — so pinned positions in `LayoutSpec.positions` are stored
   * in unscaled viewBox units regardless of zoom.
   *
   * The drag delta math (below in `startNodeDrag`) divides client-pixel
   * deltas by `zoom()` to recover viewBox-unit deltas; without that fix,
   * dragging at 2× zoom would move pins twice as far as the cursor.
   */
  const zoom = useViewZoom(() => spec().id);

  /**
   * Ref to the `.graph-view` scroll wrapper. Used for two things:
   *   1. Attaching a non-passive `wheel` listener (Ctrl/Meta + wheel ⇒ zoom).
   *      Solid's `onWheel` JSX prop registers a passive listener in some
   *      browsers, which makes `preventDefault()` a no-op — so the
   *      browser's page-scroll fires anyway. Native `addEventListener` with
   *      `{ passive: false }` is the only way to actually suppress that.
   *   2. Clearing horizontal scroll on `[reset zoom]` so the user lands
   *      back at the canvas origin, not at whatever scroll offset they
   *      had at 2× zoom.
   */
  let scrollWrapperEl: HTMLDivElement | undefined;

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

  /**
   * Map from each spec node id (leaf stepId or container id) to the
   * StateShape that exists immediately AFTER that node completes.
   * Threaded onto every drop anchor as `data-state-shape="..."` so the
   * CSS `.dragging-*` rules can grey incompatible anchors during a
   * palette drag. Re-derives whenever the spec changes.
   *
   * Pure structural fact — does NOT depend on the trace. The memo
   * subscribes only to `spec()` so a Run-without-spec-change is a no-op.
   */
  const shapesByAnchor = createMemo(() => inferShapesAtAnchors(spec(), registry));

  /**
   * The input shape of the step type currently being dragged from the
   * palette, or `null` when no palette drag is in flight (or the dragged
   * step type has no `shapeContract`). When this is `"bytes"` or
   * `"matrix4x4-bytes"`, the `.graph-view` div gains a `dragging-bytes`
   * / `dragging-matrix` class so the CSS rules dim mismatched anchors.
   *
   * "any" inputs (aux primitives) and contract-less steps both produce
   * `null` here — they never grey anything, since they can land
   * anywhere.
   */
  const draggedInputShape = createMemo<string | null>(() => {
    const t = useActiveDragStepType()();
    if (t === null) return null;
    const contract = registry.getDoc(t)?.shapeContract;
    if (!contract || contract.input === "any") return null;
    return contract.input;
  });

  /** Map of pinned positions for the active spec (memoized). */
  const pinnedMap = createMemo<ReadonlyMap<string, { x: number; y: number }>>(() => {
    const l = activeLayout();
    if (!l) return new Map();
    const m = new Map<string, { x: number; y: number }>();
    for (const [id, p] of Object.entries(l.positions)) m.set(id, p);
    return m;
  });

  /**
   * Per-source replication overrides for the active spec. Plain object so
   * it can be passed straight to `replicateHighFanoutSources` without a
   * Map ↔ object conversion at the boundary.
   */
  const replicationModes = createMemo<{ readonly [sourceId: string]: "always" | "never" }>(() => {
    const l = activeLayout();
    return l?.replicationModes ?? {};
  });

  /**
   * Auto-open the replication overrides panel when a freshly-loaded spec
   * carries per-source overrides — otherwise the user wouldn't see *why*
   * the canvas looks customized. On a clean spec (no overrides) it stays
   * closed so the toolbar real estate isn't eaten by an empty-by-intent
   * panel. After mount, the user's manual chevron clicks win until the
   * spec id changes again.
   *
   * Why `on(() => spec().id, ...)` instead of watching `replicationModes()`:
   * we want this to fire on spec load / spec switch, NOT every time the
   * user toggles an override mid-session — otherwise the close button
   * fights the auto-open the moment the user clicks an "always"/"never"
   * radio. Tying the effect to spec id keeps user intent in charge once
   * the panel is rendered.
   */
  createEffect(
    on(
      () => spec().id,
      () => {
        const hasAnyOverride = Object.keys(replicationModes()).length > 0;
        setReplicationPanelOpen(hasAnyOverride);
      },
    ),
  );

  /**
   * Endpoint pill anchors (Slice 1 of the graph-narrative plan). Walk the
   * spec's top-level entities forward (for input) / backward (for output)
   * and pick the first one whose state contract is NOT `"any"`. This skips
   * aux-only leaves like `aes.key-expansion@1` so the plaintext arrow
   * lands on the leaf that actually reads state — `initial.add-round-key`
   * for single-block AES, `split-blocks` for ECB/CBC.
   *
   * Containers (groups + iterates) are treated as state-consumers
   * unconditionally — state threads through their bodies. The state
   * spine inferred by `inferStateEdges` already chains the rest.
   *
   * Fallback when no leaf in the spec has a non-"any" contract (an empty
   * or aux-only spec): leave both anchors undefined, in which case
   * `deriveAuxGraph` falls back to `rootIds[0]` / `rootIds[last]`.
   */
  const endpointAnchors = createMemo<{ input: string | undefined; output: string | undefined }>(
    () => {
      const s = spec();
      const isStateConsumer = (n: StepNode): boolean => {
        if (n.kind !== "step") return true;
        const contract = registry.getDoc(n.type)?.shapeContract;
        // No contract: treat as consumer (avoid pointing the arrow at a
        // node the user can't even reason about). The shape-validation
        // suite enforces 100% contract coverage on the default registry,
        // so this branch only fires for hand-rolled specs in dev.
        return !contract || contract.input !== "any";
      };
      let input: string | undefined;
      let output: string | undefined;
      for (const n of s.steps) {
        if (isStateConsumer(n)) {
          input = n.id;
          break;
        }
      }
      for (let i = s.steps.length - 1; i >= 0; i--) {
        const n = s.steps[i];
        if (n && isStateConsumer(n)) {
          output = n.id;
          break;
        }
      }
      return { input, output };
    },
  );

  /**
   * Endpoint pill labels. Encrypt mode: plaintext → ciphertext.
   * Decrypt mode: labels swap (input pill reads "ciphertext", output
   * reads "plaintext"). The layout / spec direction itself does NOT
   * mirror — decryption already flows left-to-right with the inverse
   * round body, so only the I/O labels need to swap. This matches the
   * design decision from 2026-05-15 (memory: feedback_graph_design_decisions).
   *
   * **Hash-future seam.** When hash specs, MACs, or KDFs ship (planned),
   * extend this dispatch with another branch keyed off whatever cipher
   * attribute is most natural at that point. Nomenclature varies:
   * hashes use `message` / `digest`, MACs use `message` / `tag`, KDFs
   * use `ikm + salt + info` / `okm`, AEAD ciphers have TWO outputs
   * (ciphertext + tag). The shape can't be locked in today — wait for
   * the first hash spec, then add the branch. Memory pointer:
   * [[project_hash_future]].
   */
  const endpointLabels = createMemo<{ inputLabel: string; outputLabel: string }>(() =>
    useMode()() === "encrypt"
      ? { inputLabel: "plaintext", outputLabel: "ciphertext" }
      : { inputLabel: "ciphertext", outputLabel: "plaintext" },
  );

  /**
   * Root-level leaves whose `shapeContract.input === "any"` — i.e. they
   * don't consume cipher state. Today's examples: `aes.key-expansion@1`,
   * `generic.iv-load@1`, `generic.aux-load@1` (when used as a literal
   * source at root level). These get lifted above the spine row by
   * `layoutRoot` so the synthetic plaintext-pill → first-state-consumer
   * arrow doesn't visually pass through them.
   *
   * Scoped to ROOT level only: nested aux-only steps live inside a
   * container the user has already navigated into, so the visual clash
   * with the input-pill arrow doesn't arise. Containers (groups, iterates)
   * are never aux-only — state always threads through their bodies.
   */
  const auxOnlyRootIds = createMemo<ReadonlySet<string>>(() => {
    const s = spec();
    const out = new Set<string>();
    for (const n of s.steps) {
      if (n.kind !== "step") continue;
      const contract = registry.getDoc(n.type)?.shapeContract;
      // Only "any" lifts. No-contract leaves stay on the spine — they
      // might consume state, we can't tell, and a wrong lift is more
      // jarring than a missed one.
      if (contract && contract.input === "any") out.add(n.id);
    }
    return out;
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
    const labels = endpointLabels();
    const anchors = endpointAnchors();
    return deriveAuxGraph(fallback, spec(), {
      endpoints: {
        inputLabel: labels.inputLabel,
        outputLabel: labels.outputLabel,
        // Conditional spread under exactOptionalPropertyTypes: undefined
        // anchors should NOT be present as keys (they'd defeat the
        // function's `??` fallback to rootIds[0]).
        ...(anchors.input !== undefined ? { inputAnchorId: anchors.input } : {}),
        ...(anchors.output !== undefined ? { outputAnchorId: anchors.output } : {}),
      },
    });
  });

  /**
   * Post-collapse, pre-replication graph. Held as its own memo because the
   * replication-overrides panel (rendered below the toolbar) lists ALL
   * aux-edge sources visible in this graph — counting edges before
   * replication would otherwise double-count once `"always"` overrides
   * introduce replicas.
   */
  const collapsedGraph = createMemo<CipherGraph>(() => collapseGraph(rawGraph(), collapsedSet()));

  /**
   * Slice 6 — collapsed-iterate block-chip expansion. Every iterate the
   * user has collapsed AND that has a known blockSpan (post-Run) becomes
   * N parallel chip nodes (cap 6 visible + ellipsis). The transform is
   * an identity short-circuit when nothing qualifies, so single-block
   * specs and pre-Run state pay zero cost.
   *
   * Pipeline placement: AFTER `collapseGraph` (so the collapsed-set
   * info is available), BEFORE `replicateHighFanoutSources` (so chips
   * become aux-edge consumers and a `key-expansion@always` override
   * spawns one tiny replica per chip — the pedagogical composition).
   */
  const expandedGraph = createMemo<CipherGraph>(() =>
    expandCollapsedIterates(collapsedGraph(), collapsedSet()),
  );

  /** Apply optional fanout replication on top of the expanded graph.
   * Master-switch semantic: when the global toggle is off, NO replicas
   * appear — even if the user has per-source `"always"` overrides set.
   * The override panel below is hidden in that case so the user doesn't
   * wonder why their override isn't taking effect.
   */
  const replicatedGraph = createMemo<CipherGraph>(() =>
    replicate()
      ? replicateHighFanoutSources(expandedGraph(), replicationThreshold(), replicationModes())
      : expandedGraph(),
  );

  /**
   * Final display graph: drop state-spine edges that touch a lifted
   * aux-only root leaf. This is the rendering companion to the
   * `auxOnlyRootIds` lift in `layoutRoot` — having lifted the leaf OFF
   * the spine row, we also take it off the spine LOGICALLY so the eye
   * reads the canvas correctly:
   *
   *   - For AES single-block, dropping `key-expansion → initial.add-round-key`
   *     (state) means initial.add-round-key has exactly ONE incoming
   *     arrow from the plaintext direction: the endpoint pill's state
   *     edge. When replication is on, the aux replica adds a SECOND
   *     incoming arrow (`key-expansion@->initial.add-round-key →
   *     initial.add-round-key`) — that's the round-key fan-out story,
   *     intentionally distinct from the spine.
   *   - Without this filter the spine edge co-exists with the aux
   *     replica's arrow, producing three near-parallel inbound arrows
   *     at initial.add-round-key. Visually noisy and pedagogically
   *     misleading: it reads as "key-expansion's state flows into
   *     add-round-key" when in fact key-expansion's state is identity.
   *
   * Validation is unaffected — `rawWarnings` consumes `rawGraph()`,
   * not this filtered view. The dropped edges are the spec-true
   * state-passthrough edges; removing them from the display doesn't
   * change what `validateGraph` sees.
   */
  const graph = createMemo<CipherGraph>(() => {
    const g = replicatedGraph();
    const auxOnly = auxOnlyRootIds();
    if (auxOnly.size === 0) return g;
    const filteredEdges = g.edges.filter((e) => {
      if (e.kind !== "state") return true;
      return !auxOnly.has(e.from) && !auxOnly.has(e.to);
    });
    if (filteredEdges.length === g.edges.length) return g;
    return { ...g, edges: filteredEdges };
  });

  /**
   * Iterate-feedback predicate over the rendered graph. Rebuilt every
   * time `graph()` changes (collapse, replication, spec edit). Used by
   * the edge renderer to draw cross-iteration aux feedback (CBC's
   * `cbc-snapshot → cbc-xor`, OFB/CFB's analogous edges when they ship)
   * with a distinctive dashed style — without it, those backwards-in-
   * spec-order arrows look identical to normal forward edges and users
   * can mistake them for bugs.
   *
   * The same predicate is what `validateGraph` uses internally to exclude
   * these edges from cycle detection; sharing the helper keeps both
   * surfaces in sync.
   */
  const feedbackPredicate = createMemo(() => buildIterateFeedbackPredicate(graph()));

  /**
   * Sources eligible for a row in the override panel: any id appearing in
   * `edge.from` for at least one aux edge in the collapsed graph. Sorted
   * by fanout descending so the high-fanout offenders surface first.
   * Includes both leaf stepIds and iterate-container ids.
   *
   * Includes single-edge sources (fanout = 1). A user with a long arrow
   * crossing the canvas may want to replicate even a one-consumer source
   * to shorten that arrow — the original `fanout >= 2` cutoff hid that
   * use case. The visual cost is a longer override panel; tradeoff
   * favored the discoverability of "any aux edge can be locally replicated".
   */
  const replicationSources = createMemo<{ readonly id: string; readonly fanout: number }[]>(() => {
    const g = collapsedGraph();
    const counts = new Map<string, number>();
    for (const e of g.edges) {
      if (e.kind !== "aux") continue;
      counts.set(e.from, (counts.get(e.from) ?? 0) + 1);
    }
    const rows: { id: string; fanout: number }[] = [];
    for (const [id, fanout] of counts) {
      if (fanout >= 1) rows.push({ id, fanout });
    }
    rows.sort((a, b) => b.fanout - a.fanout || a.id.localeCompare(b.id));
    return rows;
  });

  const layout = createMemo(() => layoutRoot(graph(), pinnedMap(), consts(), auxOnlyRootIds()));

  /**
   * Port-spreading follow-up to Slice 7c (2026-05-16): the per-component
   * `ReplicaPlacement` memo, computed independently from `layoutRoot` so
   * the edge `<For>` block can read `sourceOf` + `rowOfSource` for the
   * `replicaTargetXOffset` helper. Cheap to recompute (single pass over
   * `graph().nodes` + `graph().edges`); memoizes against `graph()` identity
   * so reruns only happen when the graph itself swaps. We don't return
   * this from `layoutRoot` to avoid widening the pure-helper contract —
   * `layoutRoot`'s consumers (test suites, future codegen) don't need it.
   */
  const replicaPlacement = createMemo(() => buildReplicaPlacement(graph()));

  /**
   * Slice 5 — drop-gutter record shape. One record per gutter strip:
   * id == `data-drop-gutter` encoding (the same
   * `${"before"|"after"}:${siblingId}` string the drop handler
   * dispatches on), orientation drives the CSS hover style. The memo
   * itself (`dropGutters`) lives further down — after `nodesById` is in
   * scope, since the gutter builder filters out replica children.
   */
  type DropGutterRect = {
    readonly id: string;
    readonly orientation: "horizontal" | "vertical";
    readonly x: number;
    readonly y: number;
    readonly w: number;
    readonly h: number;
  };

  const containersById = createMemo(() => {
    const m = new Map<string, ContainerNode>();
    for (const c of graph().containers) m.set(c.id, c);
    return m;
  });

  /**
   * O(1) lookup for `visualEdgeTargetId` — needs `replicaOf` off each
   * node to decide whether to retarget the edge endpoint. Memoized so
   * the per-edge `toBox` reads don't rebuild the map on every reactive
   * tick.
   */
  const nodesById = createMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of graph().nodes) m.set(n.stepId, n);
    return m;
  });

  /**
   * Slice 5 — drop-gutter records for every visible container.
   *
   * Three gutter flavors per container, in a single pass:
   *   - **at-start** (`before:${firstChildId}`) — strip just above (group)
   *     or just left (iterate) of the first body child. This is the
   *     "before-first" position that was inexpressible pre-Slice 5.
   *   - **between siblings** (`before:${nextChildId}`) — strip filling the
   *     STACK_GAP / FLOW_GAP between two consecutive children. Redundant
   *     with the previous sibling's leaf-after anchor but matches user
   *     expectation that gutters exist symmetrically.
   *   - **at-end** (`after:${lastChildId}`) — strip just below (group) or
   *     just right (iterate) of the last body child.
   *
   * Excluded:
   *   - Collapsed containers (`childIds === []` after `collapseGraph`):
   *     the body isn't visible, so the gutters would point at offscreen
   *     positions.
   *   - Replica chips inside `childIds`: replicas are synthetic graph
   *     artifacts with no spec entry, so `insertStepBefore(replicaId)`
   *     would throw.
   *   - Containers with zero real (non-replica) children.
   *
   * Encoding convention: gutter id == `data-drop-gutter` value == the
   * `${kind}:${siblingId}` string the drop handler dispatches on. One
   * stable per-slot key serves the `<For>`, the live highlight signal,
   * and the handler dispatch.
   *
   * ## Structural invariant: tile the body
   *
   * A drop inside a container's body MUST resolve to a position within
   * that body — never escape to the container's parent scope. The
   * gutter cross-axis dimension (strip width for groups, strip height
   * for iterates) is therefore extended to the full body inner area:
   *
   *   - Group: every strip's X span covers `cBox.x + CONTAINER_PAD` to
   *     `cBox.x + cBox.w - CONTAINER_PAD` (the entire body's horizontal
   *     extent, not just the children's column).
   *   - Iterate: every strip's Y span covers `cBox.y + HEADER_H +
   *     CONTAINER_PAD` to `cBox.y + cBox.h - CONTAINER_PAD`
   *     (the entire body's vertical extent).
   *
   * Result: every pixel of body whitespace is covered by SOME gutter
   * strip. Paint-order + gutter-wins hit-test priority routes any drop
   * in body whitespace to its nearest semantic slot. The container's
   * outer `data-drop-anchor` can only fire on the HEADER band (where
   * no gutter renders) — preserving the Slice 8 "drop on container =
   * insert after the container in its parent" semantic without any
   * code change to the container's anchor scope.
   *
   * **Why this matters for future-proofing**: when a new container kind
   * lands (Feistel branching, hash compression body, …), the author owes
   * the project the tiling logic for their new primitive. The invariant
   * is the design constraint; the geometry is the work. The current
   * (group, iterate) cases are documented inline as the reference
   * implementations of "tile the body."
   *
   * **Acceptable edge cases** (advisor pass 2026-05-15):
   *   - Left-gutter replicas (AES groups, non-first-child consumer):
   *     replicas sit at the consumer's leaf Y, not a gap Y. Extended
   *     strips span only gap Y's, so no overlap with left-gutter
   *     replicas.
   *   - Lifted-replica row (Serpent groups + replication, or iterate
   *     bodies + replication): ~4px overlap at the at-start strip's
   *     top edge with the lifted replica chip. The gutter wins in that
   *     overlap, routing a drop on the chip's bottom 4px to
   *     `before:firstChild` instead of `after:source`. Minor; not
   *     worth refactoring for.
   */
  const dropGutters = createMemo<readonly DropGutterRect[]>(() => {
    const out: DropGutterRect[] = [];
    const cs = consts();
    const lay = layout();
    const nbi = nodesById();
    const collapsed = collapsedSet();
    for (const container of graph().containers) {
      if (collapsed.has(container.id)) continue;
      const cBox = lay.boxes.get(container.id);
      if (!cBox) continue;
      if (container.childIds.length === 0) {
        // Empty container — emit ONE sentinel gutter covering the
        // whole box. Without this, the body strip below the 22px
        // header had no gutter and no anchor walk match, so drops
        // there fell through to root-append and the user saw
        // "nothing happens" (step landed off-screen at the end of
        // the top-level spec). The full-box gutter wins over the
        // header's data-drop-anchor (gutter hit-test runs first),
        // and both routes resolve to into-start of the same
        // container, so the entire empty box becomes one
        // consistent "drop here to fill it" target with live
        // highlight feedback.
        out.push({
          id: `into-start:${container.id}`,
          // Orientation is purely a CSS hint; for a full-box gutter
          // neither axis style applies more naturally than the
          // other, but the value must be valid in the union.
          orientation: "horizontal",
          x: cBox.x,
          y: cBox.y,
          w: cBox.w,
          h: cBox.h,
        });
        continue;
      }
      // Filter to REAL (non-replica) children, in spec order. Replicas
      // are synthetic graph artifacts; `insertStepBefore(replicaId, ...)`
      // would throw because the runtime walks the spec tree.
      const realChildBoxes: { id: string; box: Box }[] = [];
      for (const childId of container.childIds) {
        const node = nbi.get(childId);
        if (node?.replicaOf !== undefined) continue;
        const cb = lay.boxes.get(childId);
        if (!cb) continue;
        realChildBoxes.push({ id: childId, box: cb });
      }
      if (realChildBoxes.length === 0) continue;

      if (container.kind === "group") {
        // Vertical stack of children → horizontal gutter strips.
        // Cross-axis (X) span = full body inner width per the
        // "tile the body" invariant documented on the memo above.
        // Going only `min(child.x) → max(child.right)` left
        // un-tiled body whitespace where the container's outer
        // `data-drop-anchor` could win, escaping the user's intent
        // out to the parent scope (the bug surfaced in the first
        // browser pass — aux-xor leaked from round.2's body to
        // root, severing the state spine).
        const minX = cBox.x + cs.CONTAINER_PAD;
        const maxRight = cBox.x + cBox.w - cs.CONTAINER_PAD;
        const stripW = maxRight - minX;
        // Between-siblings strips fill the actual STACK_GAP. Boundary
        // strips (at-start, at-end) use CONTAINER_PAD instead: the
        // boundary "space above the first child / below the last child"
        // is exactly the container's inner padding, and that's also the
        // area the user intuitively reaches for when dragging to insert
        // at the start of the body. A 6px STACK_GAP strip was too thin
        // to reliably hit on a real-world drop — cursors landing in the
        // CONTAINER_PAD area above the strip fell through to the
        // container's outer `data-drop-anchor` (which routes to
        // insert-AFTER-container-in-parent, NOT into the body), so the
        // step ended up at the wrong scope. Pinned by the
        // "at-start strip thickness" test below.
        const boundaryStripH = cs.CONTAINER_PAD;
        // biome-ignore lint/style/noNonNullAssertion: length checked above
        const first = realChildBoxes[0]!;
        // biome-ignore lint/style/noNonNullAssertion: length checked above
        const last = realChildBoxes[realChildBoxes.length - 1]!;
        // At-start: strip in the CONTAINER_PAD area immediately above
        // the first child. Positioning RELATIVE to first.y (not to the
        // container header) keeps the strip clear of any lifted-replica
        // row above the first child — when `liftH > 0` the strip sits
        // between the lifted-replica row and the first child, NOT over
        // the replica chip. (See `layoutNode`'s group branch for the
        // lift mechanics.)
        out.push({
          id: `before:${first.id}`,
          orientation: "horizontal",
          x: minX,
          y: first.box.y - boundaryStripH,
          w: stripW,
          h: boundaryStripH,
        });
        // Between consecutive siblings: fill the STACK_GAP exactly. No
        // overflow concern because STACK_GAP is the natural inter-child
        // spacing.
        for (let i = 0; i < realChildBoxes.length - 1; i++) {
          // biome-ignore lint/style/noNonNullAssertion: loop bounds
          const prev = realChildBoxes[i]!;
          // biome-ignore lint/style/noNonNullAssertion: loop bounds
          const next = realChildBoxes[i + 1]!;
          const gapTop = prev.box.y + prev.box.h;
          const gapHeight = next.box.y - gapTop;
          if (gapHeight <= 0) continue;
          out.push({
            id: `before:${next.id}`,
            orientation: "horizontal",
            x: minX,
            y: gapTop,
            w: stripW,
            h: gapHeight,
          });
        }
        // At-end: strip in the CONTAINER_PAD area immediately below
        // the last child. Symmetric to at-start.
        out.push({
          id: `after:${last.id}`,
          orientation: "horizontal",
          x: minX,
          y: last.box.y + last.box.h,
          w: stripW,
          h: boundaryStripH,
        });
        continue;
      }

      // Iterate: horizontal flow of children → vertical gutter strips.
      // Mirror of the group case with x ↔ y, STACK_GAP ↔ FLOW_GAP.
      // Cross-axis (Y) span = full body inner height per the
      // "tile the body" invariant documented on the memo above.
      // Children-Y-derived spans left the body padding above and
      // below the row un-tiled, where the container's outer
      // `data-drop-anchor` could win on near-misses.
      const minY = cBox.y + HEADER_H + cs.CONTAINER_PAD;
      const maxBottom = cBox.y + cBox.h - cs.CONTAINER_PAD;
      const stripH = maxBottom - minY;
      // Between-siblings strips use the full FLOW_GAP since that's the
      // natural gap width. At-start / at-end strips must clamp to
      // CONTAINER_PAD: with default density `FLOW_GAP=16 > CONTAINER_PAD=10`
      // an unclamped at-start strip would extend ~6px past the
      // container's left edge (and at-end past the right edge), giving
      // the user a visible hit area outside the body it represents.
      const boundaryStripW = Math.min(cs.FLOW_GAP, cs.CONTAINER_PAD);
      // biome-ignore lint/style/noNonNullAssertion: length checked above
      const first = realChildBoxes[0]!;
      // biome-ignore lint/style/noNonNullAssertion: length checked above
      const last = realChildBoxes[realChildBoxes.length - 1]!;
      out.push({
        id: `before:${first.id}`,
        orientation: "vertical",
        x: first.box.x - boundaryStripW,
        y: minY,
        w: boundaryStripW,
        h: stripH,
      });
      for (let i = 0; i < realChildBoxes.length - 1; i++) {
        // biome-ignore lint/style/noNonNullAssertion: loop bounds
        const prev = realChildBoxes[i]!;
        // biome-ignore lint/style/noNonNullAssertion: loop bounds
        const next = realChildBoxes[i + 1]!;
        const gapLeft = prev.box.x + prev.box.w;
        const gapWidth = next.box.x - gapLeft;
        if (gapWidth <= 0) continue;
        out.push({
          id: `before:${next.id}`,
          orientation: "vertical",
          x: gapLeft,
          y: minY,
          w: gapWidth,
          h: stripH,
        });
      }
      out.push({
        id: `after:${last.id}`,
        orientation: "vertical",
        x: last.box.x + last.box.w,
        y: minY,
        w: boundaryStripW,
        h: stripH,
      });
    }
    return out;
  });

  /**
   * Slice 9 — edge-aware validation.
   *
   * Validate the RAW graph (pre-collapse, pre-replication) so warnings
   * reflect spec truth, not view-state. Then remap each warning's stepId
   * to whatever node is actually visible: a hidden stepId surfaces on the
   * outermost collapsed ancestor that's still rendered, so collapsing a
   * round can't silently hide a wiring problem inside it.
   *
   * The remap mirrors `collapseGraph`'s own "outermost collapsed ancestor"
   * logic (graph.ts) — kept inline here rather than re-exported to avoid
   * coupling the renderer to a private helper.
   *
   * Replicas are produced by post-validation transforms, so warnings never
   * land on synthetic replica ids; they always target the source's
   * canonical stepId (which renders as the "main" node in `graph.nodes`).
   */
  const rawWarnings = createMemo<readonly GraphWarning[]>(() => {
    void version();
    // Two warning sources, concatenated:
    //   1. `validateShapes` runs against the spec alone — no trace
    //      required — so state-shape-mismatch dots appear the moment a
    //      shape-incompatible step is dropped from the palette.
    //   2. `validateGraph` consumes the (graph, trace) pair for the
    //      original three warning kinds (orphaned-read, unused-write,
    //      cycle), all of which need executed frames to detect.
    const shape = validateShapes(spec(), registry);
    const t = getTrace();
    return t ? [...shape, ...validateGraph(rawGraph(), t)] : shape;
  });

  /**
   * Warnings indexed by the *visible* node id (post-collapse remap). Each
   * entry is the list of warnings to surface on that node. Iterating
   * `Object.entries` (or `[...map]`) preserves insertion order — which
   * matches `validateGraph`'s stable order (orphans, then unused, then
   * cycles) so the multi-warning case reads predictably.
   */
  const warningsByVisibleId = createMemo<ReadonlyMap<string, readonly GraphWarning[]>>(() => {
    const out = new Map<string, GraphWarning[]>();
    const collapsed = collapsedSet();
    if (rawWarnings().length === 0) return out;

    // Build a lookup from any RAW node/container id to its containerPath
    // (root-first ancestor chain). The raw graph is the source of truth
    // for the path, so we read off it (not the post-collapse graph, which
    // may have replicas + remapped edges).
    const pathById = new Map<string, readonly string[]>();
    const raw = rawGraph();
    for (const n of raw.nodes) pathById.set(n.stepId, n.containerPath);
    for (const c of raw.containers) pathById.set(c.id, c.containerPath);

    /**
     * Resolve a raw stepId to the visible id it should attach to. Walk the
     * containerPath root-first and return the first collapsed ancestor;
     * otherwise return the stepId itself. Mirrors `collapseGraph`'s remap.
     */
    const remap = (stepId: string): string => {
      const path = pathById.get(stepId);
      if (!path) return stepId;
      for (const ancestor of path) {
        if (collapsed.has(ancestor)) return ancestor;
      }
      return stepId;
    };

    const push = (visibleId: string, w: GraphWarning): void => {
      const list = out.get(visibleId) ?? [];
      list.push(w);
      out.set(visibleId, list);
    };

    for (const w of rawWarnings()) {
      if (w.kind === "cycle") {
        // Attach a cycle warning to every participating visible node so
        // the user can see at least one indicator regardless of which
        // round they happen to be looking at. Dedup the visible ids so
        // a cycle that crosses two leaves inside a single collapsed
        // round produces one indicator, not two.
        const visibleParticipants = new Set<string>();
        for (const id of w.stepIds) visibleParticipants.add(remap(id));
        for (const id of visibleParticipants) push(id, w);
      } else {
        push(remap(w.stepId), w);
      }
    }

    return out;
  });

  /**
   * Click handler for a leaf node. Update the editor's selection signal —
   * `setSelectedStepId` is the single boundary that BOTH binds the
   * ParamEditor to this step AND moves the scrubber if the step has a
   * matching trace frame.
   *
   * Two behaviors are intentionally split this way:
   *   - Selection ALWAYS happens, even when no frame exists for `stepId`.
   *     That's the bug-2 fix: a freshly-dropped step is editable
   *     immediately, before the debounced auto-rerun has produced a new
   *     trace. Same for a step that lives downstream of an executor that
   *     threw and never reached this leaf.
   *   - Scrubber move happens only if a frame matches (the iterate-body
   *     `:b{i}` suffix is stripped inside `setSelectedStepId`). Replica
   *     ids (`${source}@->${consumer}`) are resolved at the call site —
   *     the caller passes the source's canonical id, so this function
   *     only ever sees real stepIds.
   */
  const handleLeafClick = (stepId: string): void => {
    void version();
    setSelectedStepId(stepId);
  };

  /**
   * Slice 8 — palette drop wiring.
   *
   * Two pieces:
   *   1. **`dragOverActive`** — a reactive flag set while a step-type drag
   *      hovers over the canvas. CSS uses it to highlight the drop zone
   *      (`.graph-drop-zone-active`) so the user gets a visual cue that the
   *      canvas accepts the drag.
   *   2. **`handleDrop` / `handleDragOver` / `handleDragLeave`** — HTML5
   *      DnD plumbing. `dragover` MUST `preventDefault()` for the drop to
   *      fire (browser default is to reject drops); the `dataTransfer.types`
   *      check ensures we only accept drags that started from our own
   *      palette (any old text drag from the OS gets ignored).
   *
   * Drop anchoring (the "WHERE in the spec" decision):
   *   - The drop event's `target` walks up via `closest("[data-drop-anchor]")`.
   *   - LeafRect's `<g>` carries `data-drop-anchor={clickTargetId}` —
   *     replica-resolved so a drop on a replica anchors to the SOURCE's
   *     real stepId (the replica's synthetic `${src}@->${consumer}` id
   *     doesn't exist in the spec; `insertStepAfter` would throw).
   *   - ContainerRect's outer `<g>` carries `data-drop-anchor={container.id}`.
   *     Per advisor + plan: drop-on-container = "after the container in
   *     its parent", NOT "into the container body". Users wanting "into
   *     round.5" drop on a specific leaf inside round.5 instead. This
   *     stays within Slice 4's `insertStepAfter` API.
   *   - No anchor found → `root-append` (drop on canvas background).
   *
   * Replica nodes route via `clickTargetId` the same way clicks do
   * (see `handleLeafClick`). Collapsed containers stay anchorable through
   * their outer `<g>` — collapsing hides children but the container's
   * graph entry persists.
   */
  const [dragOverActive, setDragOverActive] = createSignal(false);

  /**
   * Anchor id (leaf stepId or container id) the user's drag is currently
   * resolving to. Updated continuously while a step-type drag is over the
   * canvas; consumed by LeafRect / ContainerRect to render a
   * `.graph-drop-target-active` highlight so the user sees exactly WHERE
   * the drop would land before they commit.
   *
   * Without this preview, users had to drop blind and verify after the
   * fact — particularly painful when the cursor was in the gap between
   * containers and the anchor resolver fell back to root-append (drop
   * lands at the end of the spec, far from where the user intended).
   *
   * `null` means no anchor under the cursor right now (cursor between
   * elements, drag hasn't started, or drag just ended).
   */
  const [dragOverAnchorId, setDragOverAnchorId] = createSignal<string | null>(null);

  /**
   * Slice 5 — drop-gutter live highlight.
   *
   * Drop gutters are thin SVG strips between sibling leaves (and at the
   * start / end of each container body) that let the user drop a palette
   * step at any position in the body — including the "before-first"
   * position that was impossible pre-Slice 5 (the only drop anchors were
   * leaves, which insert AFTER, and container outers, which insert AFTER
   * THE CONTAINER IN ITS PARENT per Slice 8 semantics).
   *
   * `dragOverGutterId` carries the gutter's `data-drop-gutter` encoding
   * (`"before:X"` for at-start / between strips, `"after:Y"` for the
   * at-end strip) while the cursor hovers a gutter mid-drag. The gutter
   * `<rect>` reads this signal via `classList` to paint an active
   * highlight, and `handleDrop` reads the same encoding from the gutter
   * under the cursor to route to `insertStepIntoSpec`'s `before` / `after`
   * branch.
   *
   * Hit-test priority: gutters win over leaves and container outers.
   * Both `handleDragOver` and `handleDrop` walk `closest("[data-drop-gutter]")`
   * FIRST; only if that returns null do they fall back to the existing
   * `closest("[data-drop-anchor]")` walk. SVG paint order reinforces
   * this — gutters render AFTER leaves and containers (last children of
   * the canvas `<svg>` body), so they sit on top for native hit-testing.
   *
   * `null` outside of drag, OR mid-drag when the cursor isn't over any
   * gutter (it might be hovering an anchor instead).
   */
  const [dragOverGutterId, setDragOverGutterId] = createSignal<string | null>(null);

  /**
   * Slice 11 — in-app help modal open state. Toggled by the toolbar's
   * `?` button; `<GraphHelpModal>` reads it to drive the native
   * `<dialog>` open/close. Local to GraphView (not in a store) because
   * no other view cares whether the help panel is open.
   */
  const [helpOpen, setHelpOpen] = createSignal(false);

  /**
   * Check whether a drag event carries a step-type payload from our palette.
   * `dataTransfer.types` is the only field readable during `dragover` —
   * `getData` is blocked outside `drop` for security reasons. So we sniff
   * the MIME list to decide whether to call `preventDefault` (which signals
   * "this is a valid drop target" to the browser).
   */
  const isStepTypeDrag = (e: DragEvent): boolean => {
    const types = e.dataTransfer?.types;
    if (!types) return false;
    // `types` is a DOMStringList in some browsers; spread covers both.
    for (const t of types) {
      if (t === STEP_TYPE_DRAG_MIME || t === "text/plain") return true;
    }
    return false;
  };

  const handleDragOver = (e: DragEvent): void => {
    if (!isStepTypeDrag(e)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
    if (!dragOverActive()) setDragOverActive(true);
    // Resolve the same target the drop handler would use. Gutter wins
    // over anchor (Slice 5): a gutter under the cursor takes precedence
    // because it represents an explicit between-positions slot, while a
    // leaf/container anchor is the legacy after-this-thing fallback.
    // SVG paint order reinforces this — gutters render last so native
    // hit-testing hands us the gutter element first when both overlap.
    // Update both signals continuously so the highlight tracks the
    // cursor in real time.
    const target = e.target as Element | null;
    const gutterEl = target?.closest?.("[data-drop-gutter]") ?? null;
    const gutterId = gutterEl?.getAttribute("data-drop-gutter") ?? null;
    if (gutterId !== null) {
      if (gutterId !== dragOverGutterId()) setDragOverGutterId(gutterId);
      if (dragOverAnchorId() !== null) setDragOverAnchorId(null);
      return;
    }
    if (dragOverGutterId() !== null) setDragOverGutterId(null);
    const anchored = target?.closest?.("[data-drop-anchor]") ?? null;
    const anchorId = anchored?.getAttribute("data-drop-anchor") ?? null;
    if (anchorId !== dragOverAnchorId()) {
      setDragOverAnchorId(anchorId);
    }
  };

  const handleDragLeave = (e: DragEvent): void => {
    // Only clear when leaving the wrapping element entirely. `dragleave`
    // fires on every child transition too, so filtering by relatedTarget
    // keeps the highlight from flickering as the cursor crosses an
    // internal leaf/container boundary. relatedTarget=null means the
    // pointer left the document; treat as a real leave.
    const related = e.relatedTarget as Node | null;
    const current = e.currentTarget as Node | null;
    if (related && current && current.contains(related)) return;
    setDragOverActive(false);
    setDragOverAnchorId(null);
    setDragOverGutterId(null);
  };

  const handleDrop = (e: DragEvent): void => {
    e.preventDefault();
    setDragOverActive(false);
    setDragOverAnchorId(null);
    setDragOverGutterId(null);
    if (!e.dataTransfer) return;
    // Prefer the custom MIME (palette-authored); fall back to text/plain
    // for browsers that strip non-standard MIMEs on DnD payloads.
    const stepType =
      e.dataTransfer.getData(STEP_TYPE_DRAG_MIME) || e.dataTransfer.getData("text/plain");
    if (!stepType || !registry.has(stepType)) return;
    // Slice 5: gutter hit-test wins over the legacy data-drop-anchor walk.
    // A gutter under the cursor maps directly to a precise between-positions
    // slot — `before:X` (at-start / between siblings) or `after:Y`
    // (at-end). Without this priority a drop on the thin strip just above
    // a leaf would resolve to the leaf's anchor (insert AFTER the leaf) —
    // the opposite of the user's intent.
    const target = e.target as Element | null;
    const gutterEl = target?.closest?.("[data-drop-gutter]") ?? null;
    const gutterEncoding = gutterEl?.getAttribute("data-drop-gutter") ?? null;
    if (gutterEncoding !== null) {
      // Encoding shape: `${"before" | "after"}:${siblingStepId}`. Split
      // on the FIRST colon only — step ids are forbidden from containing
      // colons by the runtime's `:b{i}` block-index suffix convention,
      // but a hand-rolled spec could in principle still contain one.
      const colonIdx = gutterEncoding.indexOf(":");
      if (colonIdx > 0) {
        const kind = gutterEncoding.slice(0, colonIdx);
        const targetId = gutterEncoding.slice(colonIdx + 1);
        if (kind === "before" && targetId.length > 0) {
          insertStepIntoSpec(stepType, { kind: "before", stepId: targetId });
          return;
        }
        if (kind === "after" && targetId.length > 0) {
          insertStepIntoSpec(stepType, { kind: "after", stepId: targetId });
          return;
        }
        if (kind === "into-start" && targetId.length > 0) {
          // Empty-container sentinel gutter (see dropGutters memo):
          // the entire box of an empty container resolves here so the
          // user can drop anywhere inside the visible chip, not just
          // on the labelled header band.
          insertStepIntoSpec(stepType, { kind: "into-start", containerId: targetId });
          return;
        }
      }
      // Malformed encoding — fall through to anchor / root-append.
    }
    // Walk up from the drop target looking for the nearest `data-drop-anchor`
    // attribute. `closest` returns the element itself if it matches, so a
    // drop directly on a `<g class="graph-leaf">` finds itself. Replicas
    // carry their `clickTargetId` (source's stepId), so the anchor is
    // always a real spec id.
    //
    // Anchor-resolution dispatch (post-rescope, 2026-05-15):
    //   - Anchor is a CONTAINER id (lookup hit in `graph().containers`):
    //     the header band was hit (the only place container anchors
    //     remain, after the rescope moved `data-drop-anchor` from the
    //     outer `<g>` to the header `<rect>`). Route to
    //     `{ kind: "into-start", containerId }` — "drop on header =
    //     enter this container's body" matches user intuition. The
    //     original Slice 8 "insert after container in parent" semantic
    //     is dropped because the chip obscures the header and users
    //     couldn't tell their cursor was on it.
    //   - Anchor is a LEAF id: keep the leaf-after semantic. A drop on
    //     a leaf still means "insert immediately after this leaf in its
    //     parent."
    const anchored = target?.closest?.("[data-drop-anchor]") ?? null;
    const anchorId = anchored?.getAttribute("data-drop-anchor") ?? null;
    if (anchorId !== null && anchorId.length > 0) {
      if (containersById().has(anchorId)) {
        insertStepIntoSpec(stepType, { kind: "into-start", containerId: anchorId });
      } else {
        insertStepIntoSpec(stepType, { kind: "after", stepId: anchorId });
      }
    } else {
      insertStepIntoSpec(stepType, { kind: "root-append" });
    }
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
      // Pre-Slice-3 (no zoom) the SVG viewBox was 1:1 with rendered
      // width/height, so client-px delta mapped directly onto viewBox-unit
      // delta. Slice 3 scales rendered width/height by `zoom()` while
      // keeping the viewBox fixed at logical dimensions, so 1 client pixel
      // = (1 / zoom) viewBox units. Without dividing the delta here, a
      // drag at 2× zoom would move the pin twice as far as the cursor —
      // pins would race ahead of (or fall behind) the user's hand and
      // get persisted into localStorage at the wrong coordinates.
      //
      // Clamp to (0, 0) so the block can't be dragged off the top or left
      // of the SVG. Negative SVG coordinates fall outside the viewBox and
      // are clipped by the browser — the block becomes invisible AND
      // unclickable. The bad position would also persist in localStorage,
      // making the block unreachable across reloads until the user
      // manually edits storage. At y >= 0 the block stays inside the
      // drawn area; even when the sticky header (z-index: 1) visually
      // overlays small SVG y values at scrollTop > 0, scrolling the
      // container back to the top always reveals the block.
      const z = zoom();
      const newX = Math.max(0, startBoxX + dx / z);
      const newY = Math.max(0, startBoxY + dy / z);
      setNodePosition(spec().id, nodeId, newX, newY);
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

  /**
   * Wheel handler for "wheel over canvas = zoom" (Slice 3, design-tool
   * convention picked 2026-05-15 after the initial Ctrl+wheel mapping
   * confused users — they expected Figma-style wheel-alone zoom).
   *
   * Modifier semantics:
   *   - Plain wheel (no modifier): ZOOM. preventDefault to suppress the
   *     browser's default vertical-scroll-the-page behavior.
   *   - Shift + wheel: HORIZONTAL SCROLL the canvas. Don't preventDefault;
   *     `.graph-view`'s `overflow: auto` already scrolls horizontally,
   *     and Chrome maps Shift+wheel's deltaY onto the X axis natively.
   *     AES / Serpent canvases are wider than the viewport, so this
   *     gesture is meaningful.
   *   - Ctrl + wheel: also ZOOM (kept for muscle-memory users who
   *     learned the browser zoom convention).
   *
   * Step matches the toolbar buttons (0.10) so one wheel notch on a
   * standard mouse feels like one button click. The deltaY-magnitude
   * scale factor keeps trackpads sane: standard wheel notch is
   * |deltaY| ≈ 100 → magnitude 1 (full step per notch); trackpad scrolls
   * are tens per event but fire many events per gesture → each event a
   * fraction of a step, totalling about one step per visible gesture.
   * Capped at 1 so a high-precision device can't blast through the
   * range in one tick.
   */
  const WHEEL_ZOOM_STEP = 0.1;

  const handleWheelZoom = (ev: WheelEvent): void => {
    // Shift escape hatch: let the browser handle horizontal scroll.
    if (ev.shiftKey) return;
    // Must preventDefault to suppress the browser's default scroll. The
    // listener MUST be registered with `{ passive: false }` — Solid's
    // JSX `onWheel` prop produces a passive listener in some browsers,
    // which silently turns preventDefault into a no-op.
    ev.preventDefault();
    // Stop propagation so an outer scroll container doesn't also process
    // the same wheel event.
    ev.stopPropagation();
    // `deltaY < 0` is wheel-up / pinch-out → zoom in. Sign matches OS-
    // level zoom shortcuts.
    const direction = ev.deltaY < 0 ? 1 : -1;
    const magnitude = Math.min(1, Math.abs(ev.deltaY) / 100);
    const current = getViewZoom(spec().id);
    const next = Math.round((current + direction * WHEEL_ZOOM_STEP * magnitude) * 100) / 100;
    setViewZoom(spec().id, next);
  };

  /**
   * Attach the wheel listener directly via a ref callback (not through
   * an `onMount` reading a `let`-ref later). The callback fires once,
   * synchronously, when the wrapper element is created — eliminates a
   * timing window where `scrollWrapperEl` could be undefined at the
   * point `onMount` reads it. `capture: true` is belt-and-suspenders:
   * Chrome's page-zoom intervention sometimes wins over bubble-phase
   * listeners on scrollable containers; capture phase fires first so
   * preventDefault lands before any framework / browser handling.
   */
  const attachScrollWrapperRef = (el: HTMLDivElement): void => {
    scrollWrapperEl = el;
    el.addEventListener("wheel", handleWheelZoom, { passive: false, capture: true });
    onCleanup(() => el.removeEventListener("wheel", handleWheelZoom, { capture: true }));
  };

  /** Click handler for `[reset zoom]`. Clears horizontal scroll too. */
  const handleResetZoom = (): void => {
    resetViewZoom(spec().id);
    if (scrollWrapperEl) {
      scrollWrapperEl.scrollLeft = 0;
    }
  };

  return (
    <div class="graph-view-layout" data-testid="graph-view-layout">
      {/* Slice 8 — step palette. Lives as a left sidebar inside the graph
          view layout so it's only visible when the user is in graph mode.
          Drags from the palette dispatch DataTransfer payloads that the
          canvas's drop handlers below pick up. Doesn't subscribe to spec/
          trace signals — the registry it lists is static after module load. */}
      <StepPalette />
      <div
        ref={attachScrollWrapperRef}
        class="graph-view"
        classList={{
          "graph-drop-zone-active": dragOverActive(),
          // Activated by the module-level signal in StepPalette during a
          // palette drag. CSS rules in app.css read the data-state-shape
          // attribute on each drop anchor and dim those whose shape
          // doesn't match the dragged step's input contract.
          "dragging-bytes": draggedInputShape() === "bytes",
          "dragging-matrix": draggedInputShape() === "matrix4x4-bytes",
        }}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {/* Sticky-header wrapper. The density toolbar and replication-overrides
          panel both want to stay visible while the SVG canvas scrolls. They
          previously each set their own `position: sticky` with hardcoded top
          offsets (`top: 0` for the toolbar, `top: 32px` for the panel —
          a guess at the toolbar's rendered height), which the actual rendered
          toolbar height didn't match, so the panel slid up into the toolbar
          when the user scrolled. Wrapping both in a single sticky element
          sidesteps the math: the wrapper sticks at top: 0 and the children
          stack naturally inside it, so the panel can never overlap the
          toolbar regardless of the toolbar's true height. */}
        <div class="graph-view-sticky-header">
          {/* Density toolbar (commit 3 of the graph-readability sequence).
          Lives inside GraphView because density is graph-specific — the
          linear and JSON views ignore it. Uses `<fieldset>`/`<legend>` for
          the same a11y-friendly group semantics as the byte-format toggle
          in App.tsx (biome's useSemanticElements rule wants a semantic
          group element, not `<div role="group">`). */}
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
            {/* Commit 4: high-fanout replica toggle. When ON, sources with
            more than `replicationThreshold()` outgoing aux edges (AES
            key-expansion, Speck/Serpent key schedules) are replicated as
            small chips next to each consumer, shortening edges and reducing
            visual clutter. Off by default — the "one source, many edges"
            view is also pedagogically valuable.

            The threshold input next to the checkbox lets the user lower
            the bar (e.g. 1 to replicate everything) or raise it (e.g. 20
            to only catch Speck/Serpent schedules and leave AES alone).
            Default = DEFAULT_REPLICATION_THRESHOLD (6). Session-only —
            kept out of LayoutSpec to preserve share-URL byte stability. */}
            <label
              class="graph-replicate-toggle"
              title={`Show sources with more than ${replicationThreshold()} outgoing aux edges as small replicas next to each consumer`}
            >
              <input
                type="checkbox"
                checked={replicate()}
                onChange={(e) => setReplicationEnabled(e.currentTarget.checked)}
              />
              replicate fan-out
            </label>
            <label
              class="graph-replicate-threshold"
              title={`Sources with more than this many outgoing aux edges become replication candidates (default ${DEFAULT_REPLICATION_THRESHOLD}). Per-source overrides in the panel below take precedence.`}
            >
              <span class="graph-replicate-threshold-label">&gt;</span>
              <input
                type="number"
                class="graph-replicate-threshold-input"
                min={REPLICATION_THRESHOLD_MIN}
                max={REPLICATION_THRESHOLD_MAX}
                step={1}
                value={replicationThreshold()}
                disabled={!replicate()}
                onInput={(e) => {
                  const parsed = Number.parseInt(e.currentTarget.value, 10);
                  setReplicationThreshold(parsed);
                }}
                aria-label="Fanout threshold for replication"
              />
            </label>
            {/* Slice 3 (graph-narrative-and-zoom plan) — zoom controls.
            `margin-left: auto` on the group pushes the cluster to the right
            edge alongside the help button; the help button's own
            `margin-left: auto` then sticks to its right side (CSS flex with
            multiple `margin-left:auto` children: the first one absorbs all
            free space, the rest pack normally).

            Buttons step by 0.1; the wheel handler uses 0.05 (finer) so
            trackpad pinch feels smoother. Range is hard-clamped to
            [VIEW_ZOOM_MIN, VIEW_ZOOM_MAX] in the store so the disabled
            states here are purely a UX hint — clicking [+] at MAX is a
            harmless no-op (the clamp returns MAX). */}
            {/* No `role="group"` here even though the buttons form one — biome's
            `useSemanticElements` would push us to a `<fieldset>`, but the
            zoom controls already live inside the outer
            `.graph-view-toolbar` `<fieldset>`, and nesting fieldsets is
            semantically odd. Each button carries its own `aria-label`, so
            the assistive surface is fine without an outer group element. */}
            <div
              class="graph-view-zoom"
              title="Zoom the graph canvas. Mouse wheel over the canvas also zooms (Shift+wheel scrolls horizontally)."
            >
              {/* Label matches the visual treatment of the "density" `<legend>`
              at the start of the toolbar — same `.graph-view-toolbar-label`
              class — so users get an explicit name on the right-side
              cluster too, parallel to the density label on the left. */}
              <span class="graph-view-toolbar-label" aria-hidden="true">
                zoom
              </span>
              <button
                type="button"
                class="graph-view-zoom-button"
                onClick={() => stepViewZoom(spec().id, -1)}
                disabled={zoom() <= VIEW_ZOOM_MIN}
                aria-label="Zoom out"
                title={`Zoom out (min ${Math.round(VIEW_ZOOM_MIN * 100)}%)`}
              >
                −
              </button>
              <span
                class="graph-view-zoom-readout"
                aria-live="polite"
                data-testid="graph-view-zoom-readout"
              >
                {Math.round(zoom() * 100)}%
              </span>
              <button
                type="button"
                class="graph-view-zoom-button"
                onClick={() => stepViewZoom(spec().id, 1)}
                disabled={zoom() >= VIEW_ZOOM_MAX}
                aria-label="Zoom in"
                title={`Zoom in (max ${Math.round(VIEW_ZOOM_MAX * 100)}%)`}
              >
                +
              </button>
              <button
                type="button"
                class="graph-view-zoom-button graph-view-zoom-reset"
                onClick={handleResetZoom}
                disabled={zoom() === VIEW_ZOOM_DEFAULT}
                aria-label="Reset zoom"
                title={`Reset zoom to ${Math.round(VIEW_ZOOM_DEFAULT * 100)}%`}
              >
                reset
              </button>
            </div>
            {/* Slice 11 — in-app help button. Pushed to the right edge of
            the toolbar via `margin-left: auto` in `.graph-view-help-button`
            so it doesn't visually compete with the density + replicate
            controls on the left. The actual help content lives in
            `docs/help/graph-view.md` and renders via `GraphHelpModal`. */}
            <button
              type="button"
              class="graph-view-help-button"
              onClick={() => setHelpOpen(true)}
              title="What does this view show? How do I drag and drop?"
              aria-label="Show graph view help"
            >
              ?
            </button>
          </fieldset>
          {/* Commit 5: per-source replication overrides. Visible only when
          the global toggle is ON — master-switch semantic means an
          override panel is meaningless when nothing is replicated. The
          panel lists every aux-edge source with fanout ≥ 2, sorted desc
          (high-fanout offenders first); per row, three radio-style
          buttons mirror the byte-format toggle's affordance.

          Clicking the already-active button is a no-op (no toggle-back).
          To go back to "auto" the user picks the "auto" button. The
          store maps "auto" → null (clears the override). The panel sticks
          to the top of the scroll wrapper like the toolbar so it stays
          visible at far-right scroll positions. */}
          <Show when={replicate() && replicationSources().length > 0}>
            <div class="graph-replication-panel">
              {/* Header is a clickable button — toggles the panel body open
                or closed. The chevron rotates 90° via CSS based on the
                `data-open` attribute so users get an animated affordance
                rather than a static glyph. Tests assert on
                `data-testid="replication-panel-toggle"` + the body's
                presence-or-absence. */}
              <button
                type="button"
                class="graph-replication-panel-header"
                data-testid="replication-panel-toggle"
                data-open={replicationPanelOpen() ? "true" : "false"}
                aria-expanded={replicationPanelOpen() ? "true" : "false"}
                onClick={toggleReplicationPanelOpen}
                title={
                  replicationPanelOpen()
                    ? "Collapse replication overrides"
                    : "Expand replication overrides"
                }
              >
                <span class="graph-replication-panel-chevron" aria-hidden="true">
                  ▸
                </span>
                replication overrides
                <span class="graph-replication-panel-hint">
                  auto = follow global threshold ({replicationThreshold()})
                </span>
              </button>
              <Show when={replicationPanelOpen()}>
                {/* Body wrapper caps the panel's vertical real estate so
                    the open panel can't obstruct an unbounded amount of
                    canvas. CSS (`.graph-replication-panel-body`)
                    applies `max-height: 30vh` + `overflow-y: auto`, so
                    ciphers with many overridable sources scroll the
                    list internally rather than pushing the rest of the
                    sticky header (and the canvas it covers) further
                    down. For the typical 3-source AES-128 case the
                    cap never engages — the rows are ~24 px each and
                    well under 30vh. */}
                <div class="graph-replication-panel-body">
                  <For each={replicationSources()}>
                    {(src) => {
                      const currentMode = createMemo<"auto" | "always" | "never">(() => {
                        const m = replicationModes()[src.id];
                        return m ?? "auto";
                      });
                      return (
                        <div
                          class="graph-replication-row"
                          data-testid={`replication-row-${src.id}`}
                        >
                          <span class="graph-replication-row-id" title={src.id}>
                            {src.id}
                          </span>
                          <span class="graph-replication-row-fanout">
                            {src.fanout} {src.fanout === 1 ? "edge" : "edges"}
                          </span>
                          <div class="format-toggle">
                            <button
                              type="button"
                              classList={{ active: currentMode() === "auto" }}
                              onClick={() => setReplicationMode(spec().id, src.id, null)}
                              title="Defer to the global threshold"
                            >
                              auto
                            </button>
                            <button
                              type="button"
                              classList={{ active: currentMode() === "always" }}
                              onClick={() => setReplicationMode(spec().id, src.id, "always")}
                              title="Always replicate this source"
                            >
                              always
                            </button>
                            <button
                              type="button"
                              classList={{ active: currentMode() === "never" }}
                              onClick={() => setReplicationMode(spec().id, src.id, "never")}
                              title="Never replicate this source"
                            >
                              never
                            </button>
                          </div>
                        </div>
                      );
                    }}
                  </For>
                </div>
              </Show>
            </div>
          </Show>
          {/* Value-inspector panel. Mounted unconditionally so the
            collapsed-header toggle is always reachable; the body renders
            value/empty content based on the selected target — an edge,
            leaf, endpoint pill, or block chip — picked via click-only
            (no hover).

            Reactivity: the value memo depends on selectedTarget(), the
            current frame index (for block-aware lookup), useTraceVersion
            (re-run swaps the trace), and the active byte format.
            Missing any of those would produce a stale render. */}
          <div class="graph-value-inspector-panel">
            <button
              type="button"
              class="graph-value-inspector-panel-header"
              data-testid="value-inspector-panel-toggle"
              data-open={inspectorPanelOpen() ? "true" : "false"}
              aria-expanded={inspectorPanelOpen() ? "true" : "false"}
              onClick={toggleInspectorPanelOpen}
              title={inspectorPanelOpen() ? "Collapse value inspector" : "Expand value inspector"}
            >
              <span class="graph-value-inspector-panel-chevron" aria-hidden="true">
                ▸
              </span>
              value inspector
              <span class="graph-value-inspector-panel-hint">click an edge or node</span>
            </button>
            <Show when={inspectorPanelOpen()}>
              <ValueInspectorBody
                selectedTarget={selectedTarget}
                edges={() => graph().edges}
                spec={spec}
                frameIndex={frameIndex}
                version={version}
                byteFormat={byteFormat}
              />
            </Show>
          </div>
        </div>
        <Show
          when={graph().nodes.length > 0 || graph().containers.length > 0}
          fallback={<div class="muted">no nodes to display</div>}
        >
          <svg
            class="graph-view-svg"
            width={layout().canvasW * zoom()}
            height={layout().canvasH * zoom()}
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
                const containerWarnings = createMemo(
                  () => warningsByVisibleId().get(container.id) ?? [],
                );
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
                        warnings={containerWarnings()}
                        stateShape={shapesByAnchor().get(container.id) ?? ""}
                        // Live preview during a palette drag: highlights this
                        // container whenever the cursor's resolved anchor
                        // (`closest("[data-drop-anchor]")`) is THIS container.
                        isDropTargetActive={dragOverAnchorId() === container.id}
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
                // Slice-2 follow-up: visually terminate replica→iterate-
                // container aux edges at the iterate body's FIRST child,
                // not at the iterate container itself. The edge data model
                // is unchanged (`edge.to` still points at the iterate, so
                // Slice 9's validator and Slice 4's inspector keep reading
                // the right consumer); only the rendered arrowhead anchor
                // shifts. For everything else this returns `edge.to`
                // unchanged.
                const toBox = createMemo(() => {
                  const targetId = visualEdgeTargetId(edge, nodesById(), containersById());
                  return layout().boxes.get(targetId);
                });
                const eKey = encodeEdgeKey(edge);
                // Port-spreading follow-up to Slice 7c (2026-05-16): for
                // replica-sourced edges in a multi-source graph, shift the
                // target attach point by one slot per globally-stable
                // source row so a fan-IN of N replicas distributes across
                // N points on the consumer's top edge instead of all
                // converging at the center. Helper returns 0 for non-
                // replica edges and for `total === 1` (single-source
                // ciphers — the aux-only baseline today), so this is a
                // no-op for every shipped spec unless the user opts more
                // than one source into `always`. PORT_GAP scales with
                // LEAF_W so the spread tracks density (~13 px at normal,
                // ~10 at compact, ~16 at comfortable); clamped to ≥6 so
                // the minimum is still visually distinct at tight
                // densities.
                const targetXOffset = createMemo(() => {
                  const portGap = Math.max(6, Math.round(consts().LEAF_W / 10));
                  return replicaTargetXOffset(edge, replicaPlacement(), portGap);
                });
                // Straight-line + offset-start-point + start-dot
                // (2026-05-16, replacement for the curved-edge
                // prototype): row-k replica edges (k ≥ 1) get a
                // horizontal shift to their SOURCE x so the arrow
                // tail emerges from a non-centred point on the
                // replica's bottom edge. Row 0 stays centred. Zero
                // for non-replicas and single-source graphs.
                const sourceXOffset = createMemo(() =>
                  replicaSourceXOffset(edge, replicaPlacement(), consts().REPLICA_SOURCE_X_STEP),
                );
                // Whether this edge originates from a fan-out replica.
                // Gates the straight-line path variant + the
                // start-dot render inside EdgePath. Memoized so the
                // boolean reference is stable per <For> iteration —
                // small win, mostly for self-documentation.
                const isReplicaEdgeMemo = createMemo(() => isReplicaEdge(edge, replicaPlacement()));
                return (
                  <Show when={fromBox() && toBox()}>
                    <EdgePath
                      // biome-ignore lint/style/noNonNullAssertion: <Show> guard above
                      from={fromBox()!}
                      // biome-ignore lint/style/noNonNullAssertion: <Show> guard above
                      to={toBox()!}
                      auxKey={edge.auxKey}
                      kind={edge.kind}
                      // Cross-iteration aux feedback (e.g. CBC's
                      // cbc-snapshot → cbc-xor): renders dashed so the
                      // user can read "this is iteration-N → iteration-
                      // N+1, not within-iteration flow" at a glance.
                      isFeedback={feedbackPredicate()(edge)}
                      edgeKey={eKey}
                      // `selectedTarget()` dep ensures Solid re-runs this when
                      // the selection changes. `isEdgeSelected` reads the
                      // store-level signal too (redundant tracking is harmless
                      // and keeps the helper's API stable for non-Solid callers).
                      isSelected={selectedTarget() !== null && isEdgeSelected(eKey)}
                      targetXOffset={targetXOffset()}
                      sourceXOffset={sourceXOffset()}
                      isReplicaEdge={isReplicaEdgeMemo()}
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
              click; when not, an explicit click handler stays on the <g>.

              Synthetic endpoint pills (Slice 1) — `__cipher_input__` and
              `__cipher_output__` — branch out early to an EndpointPill
              component: rounded chip, no drop anchor, no drag, no click-
              scrub, no delete, no warnings. */}
            <For each={graph().nodes}>
              {(node) => {
                if (node.endpointSide !== undefined) {
                  const epBox = createMemo(() => layout().boxes.get(node.stepId));
                  // Narrow the union for the typechecker — Solid's <Show>
                  // can't carry the discriminator through without it.
                  const side = node.endpointSide;
                  const pillId = node.stepId;
                  return (
                    <Show when={epBox()}>
                      {(b) => (
                        <EndpointPill
                          box={b()}
                          side={side}
                          label={node.label}
                          // Pills aren't spec nodes (no scrub target), so the
                          // click ONLY toggles inspector selection. Inspector
                          // returns the "endpoint" status — descriptive label,
                          // no value formatting.
                          isSelected={selectedTarget() !== null && isNodeSelected(pillId)}
                          onClick={() => toggleSelectedNode(pillId)}
                        />
                      )}
                    </Show>
                  );
                }
                const box = createMemo(() => layout().boxes.get(node.stepId));
                const isInsideIterate = node.containerPath.some((id) => {
                  const c = containersById().get(id);
                  return c?.kind === "iterate";
                });
                const isRootLevel = node.containerPath.length === 0;
                // Two flavors of "synthetic" leaf — both suppress drag /
                // delete and route clicks to a source id, but they reach
                // the renderer via different graph fields:
                //   - aux replicas (`replicaOf`) — auto-positioned ABOVE
                //     their consumer by `buildReplicaPlacement`'s second
                //     pass; click scrubs to the source's trace frame.
                //   - block chips (`blockChipOf`, Slice 6) — laid out
                //     normally at the iterate's old slot; click routes
                //     to the iterate id (today a no-op, matching the
                //     "click a collapsed iterate chip" baseline). They
                //     do NOT enter `isReplica` in `buildReplicaPlacement`
                //     so the layout machinery treats them as ordinary
                //     leaves; the styling/no-drag/no-delete behavior is
                //     applied here at the render boundary instead.
                const isAuxReplica = node.replicaOf !== undefined;
                const isBlockChip = node.blockChipOf !== undefined;
                const isReplicaLike = isAuxReplica || isBlockChip;
                const clickTargetId = node.blockChipOf ?? node.replicaOf ?? node.stepId;
                // Inspector identity differs from scrub identity for chips:
                //   - Block chip: scrub routes to the iterate id (`clickTargetId`)
                //     because chips have no trace frame of their own, but the
                //     INSPECTOR wants the chip id (`node.stepId` =
                //     `${iterateId}@block${i}`) so `lookupNodeValue` resolves
                //     to that block's per-block payload.
                //   - Aux replica: the replica's synthetic id
                //     (`${source}@->${consumer}`) has no lookup target, so
                //     the inspector uses the source id (= `clickTargetId`),
                //     matching scrub behavior.
                //   - Regular leaf: both ids coincide.
                const inspectorTargetId = isBlockChip
                  ? node.stepId
                  : (node.replicaOf ?? node.stepId);
                // exactOptionalPropertyTypes is on, so we conditionally spread
                // blockSpan rather than passing `undefined` as a real value.
                const blockSpanProps =
                  isInsideIterate && node.blockSpan !== undefined
                    ? { blockSpan: node.blockSpan }
                    : {};
                // Conditional spread for the drag handler — only present on
                // root-level leaves AND not replica-like (replicas + chips
                // are both auto / synthetic placements that shouldn't be
                // user-pinned).
                const dragProps =
                  isRootLevel && !isReplicaLike
                    ? {
                        onPointerDown: (e: PointerEvent) =>
                          startNodeDrag(node.stepId, e, () => {
                            // Click fallback (sub-threshold drag release) on
                            // a draggable leaf — keep both behaviors aligned
                            // with the non-draggable onClick path below:
                            // scrub the trace AND toggle inspector selection.
                            handleLeafClick(clickTargetId);
                            toggleSelectedNode(inspectorTargetId);
                          }),
                      }
                    : {};
                const leafWarnings = createMemo(() => warningsByVisibleId().get(node.stepId) ?? []);
                return (
                  <Show when={box()}>
                    {(b) => (
                      <LeafRect
                        stepId={node.stepId}
                        // `node.label` covers all three cases: ordinary
                        // leaves carry `node.label === node.stepId` (so
                        // the dot-strip shortener still produces e.g.
                        // `sub-bytes`), aux replicas carry the source's
                        // bare id (e.g. `key-expansion`, no dot to
                        // strip), block chips carry `block N` /
                        // `+N more blocks` directly. Reading from
                        // `node.label` rather than `clickTargetId`
                        // means the chip's display text wins over the
                        // iterate id it'd otherwise resolve to.
                        label={shortLeafLabel(node.label)}
                        stepType={node.stepType}
                        box={b()}
                        draggable={isRootLevel && !isReplicaLike}
                        isReplica={isReplicaLike}
                        dropAnchorId={clickTargetId}
                        // Reactive: the JSX expression re-evaluates when
                        // dragOverAnchorId() changes, and Solid forwards
                        // the new prop value through to LeafRect — which
                        // toggles `.graph-drop-target-active` accordingly.
                        isDropTargetActive={dragOverAnchorId() === clickTargetId}
                        {...blockSpanProps}
                        {...dragProps}
                        onClick={() => {
                          // Two effects on a leaf click:
                          //   1. handleLeafClick scrubs the trace + binds
                          //      the ParamEditor (existing behavior).
                          //   2. toggleSelectedNode populates the value
                          //      inspector with this leaf's state value
                          //      (or for chips: the per-block payload).
                          // Re-clicking the same leaf clears the inspector
                          // selection but keeps the scrub position — the
                          // two are intentionally independent.
                          handleLeafClick(clickTargetId);
                          toggleSelectedNode(inspectorTargetId);
                        }}
                        // `selectedTarget()` dep so Solid re-renders this leaf
                        // when the global selection changes (and another leaf
                        // needs to lose its halo). The `isNodeSelected` helper
                        // reads the same signal — redundant tracking is fine.
                        isSelected={selectedTarget() !== null && isNodeSelected(inspectorTargetId)}
                        warnings={leafWarnings()}
                        stateShape={shapesByAnchor().get(clickTargetId) ?? ""}
                      />
                    )}
                  </Show>
                );
              }}
            </For>

            {/* Slice 5 — drop gutters. Rendered LAST so they sit on top
              of leaves and containers for native SVG hit-testing: a
              cursor over the thin strip just above a leaf hits the
              gutter element, not the leaf below it. CSS keeps them
              invisible + non-interactive when no palette drag is
              active (`pointer-events: none; opacity: 0`); the parent
              `.graph-drop-zone-active` class flipped by
              `handleDragOver` switches them on during drag. */}
            <For each={dropGutters()}>
              {(g) => (
                <rect
                  class="graph-drop-gutter"
                  classList={{
                    "graph-drop-gutter-vertical": g.orientation === "vertical",
                    "graph-drop-gutter-horizontal": g.orientation === "horizontal",
                    "graph-drop-gutter-active": dragOverGutterId() === g.id,
                  }}
                  data-drop-gutter={g.id}
                  x={g.x}
                  y={g.y}
                  width={g.w}
                  height={g.h}
                />
              )}
            </For>
          </svg>
        </Show>
      </div>
      {/* Slice 11 — in-app help modal. Mounted at the layout root (sibling
      to the palette + scroll wrapper) so its `<dialog>` backdrop can
      cover the whole graph view, not just the SVG canvas. The modal owns
      its own `<dialog>` lifecycle; we only flip the open signal here. */}
      <GraphHelpModal isOpen={helpOpen} onClose={() => setHelpOpen(false)} />
    </div>
  );
};

// ─── Pieces ────────────────────────────────────────────────────────────────

/**
 * One-line human-readable summary of a `GraphWarning`. Used both as the
 * `<title>` text on the warning dot (native browser tooltip) and as the
 * inline message below the node when the dot is clicked.
 *
 * Format goal: a screen-reader user hearing this without visual context
 * should understand the issue and which step/aux-key it pertains to.
 * "Orphaned read of 'roundKey.0'" tells the user what's missing.
 */
const formatWarning = (w: GraphWarning): string => {
  switch (w.kind) {
    case "orphaned-read":
      return `Orphaned read of aux key '${w.auxKey}' — no upstream step writes it.`;
    case "unused-write":
      return `Unused write of aux key '${w.auxKey}' — no downstream step reads it.`;
    case "cycle":
      return `Cycle in dataflow: ${w.stepIds.join(" → ")} → ${w.stepIds[0]}.`;
    case "state-shape-mismatch":
      // Both `expected` and `got` are StateShape strings ("bytes",
      // "matrix4x4-bytes", etc.). Surfacing them raw matches the
      // executor's own throw text so the warning and the Run-time
      // exception read consistently.
      return `Expects state shape '${w.expected}', but '${w.got}' arrives here.`;
  }
};

/** Side length of the warning indicator's hit area (CSS pixels). Sized for
 * a comfortable click target without crowding the leaf rectangle's label. */
const WARNING_DOT_SIZE = 12;
/** Inset from the leaf/container's top-right corner. */
const WARNING_DOT_INSET = 2;

/**
 * SVG warning indicator. Rendered as a `<g>` with a circle + an exclamation
 * glyph and a `<title>` carrying the formatted message. Native browser
 * tooltips on hover; the click handler relays up so the parent can also
 * toggle inline display elsewhere (today: no inline display — the title
 * tooltip is the v1 affordance).
 */
const WarningGlyph = (props: {
  x: number;
  y: number;
  warnings: readonly GraphWarning[];
}) => (
  <g
    class="graph-warning-dot"
    data-testid="graph-warning-dot"
    transform={`translate(${props.x}, ${props.y})`}
  >
    <title>{props.warnings.map(formatWarning).join("\n")}</title>
    <circle
      class="graph-warning-dot-circle"
      cx={WARNING_DOT_SIZE / 2}
      cy={WARNING_DOT_SIZE / 2}
      r={WARNING_DOT_SIZE / 2}
    />
    <text
      class="graph-warning-dot-glyph"
      x={WARNING_DOT_SIZE / 2}
      y={WARNING_DOT_SIZE / 2 + 0.5}
      text-anchor="middle"
      dominant-baseline="central"
    >
      !
    </text>
  </g>
);

/**
 * SVG delete affordance. Same chip pattern as the warning dot (matching
 * 12-px circle + glyph) but tinted red and reading `×`. Hidden by default
 * via CSS (`opacity: 0`), revealed on parent leaf/container hover. Click
 * fires the supplied handler — typically `removeStepFromSpec(stepId)`.
 *
 * Stops propagation so the click doesn't bubble up to the parent
 * `<g>`'s click/drag handlers (which would scrub the trace or start a
 * drag, neither of which the user wants when they meant "delete").
 */
/**
 * SVG duplicate affordance for AES round groups. Same hover-reveal chip
 * pattern as `DeleteGlyph` — a 12-px circle with a `+` glyph, hidden
 * until the parent container is hovered. Click fires `onDuplicate`.
 *
 * Rendered only on `round.N` containers that have a `round.{N+1}` sibling
 * AND on `inv-round.N` containers with `N > 0` — `isRoundDuplicatable`
 * in the spec store gates this. The restriction sidesteps the
 * "duplicating the final round auto-mirrors into a nonexistent
 * counterpart" half-state.
 */
const DuplicateGlyph = (props: {
  x: number;
  y: number;
  /** Container id for the tooltip + testid. */
  containerId: string;
  onDuplicate: () => void;
}) => (
  <g
    class="graph-duplicate-button"
    data-testid={`graph-duplicate-${props.containerId}`}
    transform={`translate(${props.x}, ${props.y})`}
    onClick={(e) => {
      e.stopPropagation();
      props.onDuplicate();
    }}
    onPointerDown={(e) => {
      // Same rationale as DeleteGlyph: prevent the parent's drag-start
      // from claiming the gesture.
      e.stopPropagation();
    }}
    onKeyDown={(e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        e.stopPropagation();
        props.onDuplicate();
      }
    }}
  >
    <title>Duplicate {props.containerId}</title>
    <circle
      class="graph-duplicate-button-circle"
      cx={WARNING_DOT_SIZE / 2}
      cy={WARNING_DOT_SIZE / 2}
      r={WARNING_DOT_SIZE / 2}
    />
    <text
      class="graph-duplicate-button-glyph"
      x={WARNING_DOT_SIZE / 2}
      y={WARNING_DOT_SIZE / 2 + 0.5}
      text-anchor="middle"
      dominant-baseline="central"
    >
      +
    </text>
  </g>
);

const DeleteGlyph = (props: {
  x: number;
  y: number;
  /** Step id for the tooltip + testid. The handler is responsible for
   *  resolving the id to a real removal. */
  stepId: string;
  onDelete: () => void;
}) => (
  <g
    class="graph-delete-button"
    data-testid={`graph-delete-${props.stepId}`}
    transform={`translate(${props.x}, ${props.y})`}
    onClick={(e) => {
      e.stopPropagation();
      props.onDelete();
    }}
    onPointerDown={(e) => {
      // Stop pointerdown too, otherwise the parent's startNodeDrag
      // claims the gesture and the click handler never fires (sub-
      // threshold release on a moved-but-not-far-enough pointer is
      // possible but uneven).
      e.stopPropagation();
    }}
    onKeyDown={(e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        e.stopPropagation();
        props.onDelete();
      }
    }}
  >
    <title>Delete {props.stepId}</title>
    <circle
      class="graph-delete-button-circle"
      cx={WARNING_DOT_SIZE / 2}
      cy={WARNING_DOT_SIZE / 2}
      r={WARNING_DOT_SIZE / 2}
    />
    <text
      class="graph-delete-button-glyph"
      x={WARNING_DOT_SIZE / 2}
      y={WARNING_DOT_SIZE / 2 + 0.5}
      text-anchor="middle"
      dominant-baseline="central"
    >
      ×
    </text>
  </g>
);

const LeafRect = (props: {
  stepId: string;
  label: string;
  stepType: string;
  box: Box;
  blockSpan?: number;
  draggable: boolean;
  /** True for replica nodes (commit 4 of the graph-readability sequence) —
   * adds `.graph-leaf-replica` class so CSS can distinguish a visual
   * reference (dashed border, lighter fill) from a real leaf. */
  isReplica: boolean;
  /**
   * The anchor id used for a palette drop landing on this leaf (Slice 8).
   * For replicas the parent passes the SOURCE's stepId (via
   * `clickTargetId`) — the replica's synthetic `${src}@->${consumer}` id
   * doesn't exist in the spec, so the source's id is what
   * `insertStepAfter` actually needs.
   */
  dropAnchorId: string;
  /** Present only when draggable. The parent wires this to `startNodeDrag`
   * with the leaf's onClick as the sub-threshold fallback, so clicks still
   * scrub the trace and drags pin the position. */
  onPointerDown?: (e: PointerEvent) => void;
  /** Used by the keyboard handler always; also used by mouse when not
   * draggable (a click that didn't go through the drag handler). */
  onClick: () => void;
  /** Slice 9 — validation warnings to surface on this leaf. Empty array
   * is the happy path (no indicator rendered). Multi-warning case: a
   * single glyph with all messages joined in the title tooltip. */
  warnings: readonly GraphWarning[];
  /**
   * State shape that exists at this leaf's position (i.e. AFTER it runs
   * — but for drop-anchor purposes, "after this step" == "before the
   * next step", which is what insertStepAfter creates). Empty string when
   * the spec walker didn't visit this id (shouldn't happen for shipped
   * specs, but kept defensive). Read by CSS via `data-state-shape` to
   * decide whether to grey this anchor during a palette drag.
   */
  stateShape: string;
  /**
   * True when the current palette drag would land at this leaf's anchor
   * if released now. Toggles `.graph-drop-target-active` so CSS can
   * paint a subtle highlight, giving the user a live preview of where
   * the drop will commit. Always false when no drag is in progress.
   */
  isDropTargetActive: boolean;
  /**
   * True when this leaf is the currently-selected value-inspector
   * target. Applies the `.graph-leaf-selected` halo class so the user
   * can find the inspected node at a glance — matches the
   * `.graph-edge-selected` halo on edges for visual consistency.
   */
  isSelected: boolean;
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
      class={`graph-leaf${props.draggable ? " graph-leaf-draggable" : ""}${
        props.isReplica ? " graph-leaf-replica" : ""
      }`}
      classList={{
        "graph-drop-target-active": props.isDropTargetActive,
        "graph-leaf-selected": props.isSelected,
      }}
      data-drop-anchor={props.dropAnchorId}
      data-state-shape={props.stateShape}
      // Always-present stepId hook for tests + browser tooling. Mirrors
      // the existing `graph-container-header-${id}` / `graph-container-
      // chevron-${id}` testid pattern. Replica chips carry their
      // synthetic `${src}@->${consumer}` id here, which is the only
      // stable handle a Playwright spec has on them (their <title>
      // text contains the same id but is brittle to the title-format
      // changes).
      data-testid={`graph-leaf-${props.stepId}`}
      // `tabindex="0"` puts the leaf in the natural keyboard tab order so
      // Delete/Backspace can target the focused node. Replicas are
      // skipped — they're visual references, not editable nodes.
      tabindex={props.isReplica ? undefined : 0}
      onPointerDown={props.onPointerDown}
      onClick={props.draggable ? undefined : props.onClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onClick();
        } else if (e.key === "Delete" && !props.isReplica) {
          // Delete-only by design — Backspace is reserved for future
          // navigation/back-style use so we don't bind it to a
          // destructive action.
          e.preventDefault();
          removeStepFromSpec(props.stepId);
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
      <Show when={props.warnings.length > 0}>
        <WarningGlyph
          x={props.box.x + props.box.w - WARNING_DOT_SIZE - WARNING_DOT_INSET}
          y={props.box.y + WARNING_DOT_INSET}
          warnings={props.warnings}
        />
      </Show>
      {/* Delete affordance — top-LEFT corner (warnings take top-right).
          Suppressed on replicas: a replica is a visual reference to its
          source, not an editable node. Deleting the source via its own
          × naturally removes the replica too on next derive. */}
      <Show when={!props.isReplica}>
        <DeleteGlyph
          x={props.box.x + WARNING_DOT_INSET}
          y={props.box.y + WARNING_DOT_INSET}
          stepId={props.stepId}
          onDelete={() => removeStepFromSpec(props.stepId)}
        />
      </Show>
    </g>
  );
};

/**
 * Synthetic endpoint pill — Slice 1 of the graph-narrative plan.
 *
 * Rounded rectangle (rx = h/2 produces a pill shape) at the canvas left
 * (`side="input"`, labelled "plaintext" / "ciphertext") or canvas right
 * (`side="output"`, labelled "ciphertext" / "plaintext"). Visually
 * distinct from the rectangular leaves so a new viewer reads it as
 * "this is where data enters / exits the cipher", not as another step.
 *
 * Limited affordances:
 *   - no `data-drop-anchor` (palette drops can't target the pill)
 *   - no scrub-on-click (pill has no trace frame); click ONLY toggles
 *     inspector selection
 *   - `tabindex=0` for keyboard reachability of the click action only;
 *     Enter/Space mirror the click
 *   - no delete glyph (it's not a spec node; can't be removed)
 *   - no warnings overlay (validation skips synthetic ids by construction)
 *
 * The label-swap on decrypt (input pill reads "ciphertext", output reads
 * "plaintext") is handled in the parent `endpointLabels` memo; this
 * component just renders whatever label it's given.
 */
const EndpointPill = (props: {
  box: Box;
  side: "input" | "output";
  label: string;
  /** Click toggles inspector selection on this pill. Endpoint pills
   *  carry no scrub target, so this is the ONLY behavior on click. */
  onClick: () => void;
  /** True when the pill is the currently-selected inspector target.
   *  Applies `.graph-endpoint-selected` halo class. */
  isSelected: boolean;
}) => (
  <g
    class={`graph-endpoint-pill graph-endpoint-${props.side}`}
    classList={{ "graph-endpoint-selected": props.isSelected }}
    tabindex={0}
    onClick={props.onClick}
    onKeyDown={(e) => {
      // Mirror Enter/Space → click for keyboard users. Biome's
      // useKeyWithClickEvents lint requires this when onClick is set on
      // a non-button element.
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        props.onClick();
      }
    }}
  >
    <title>
      {props.side === "input" ? "Cipher input — " : "Cipher output — "}
      {props.label}
    </title>
    <rect
      class="graph-endpoint-rect"
      x={props.box.x}
      y={props.box.y}
      width={props.box.w}
      height={props.box.h}
      rx={props.box.h / 2}
      ry={props.box.h / 2}
    />
    <text
      class="graph-endpoint-label"
      x={props.box.x + props.box.w / 2}
      y={props.box.y + props.box.h / 2}
      text-anchor="middle"
      dominant-baseline="central"
    >
      {props.label}
    </text>
  </g>
);

const ContainerRect = (props: {
  container: ContainerNode;
  box: Box;
  isCollapsed: boolean;
  consts: LayoutConstants;
  onDragStart: (e: PointerEvent) => void;
  onToggleCollapse: () => void;
  /** Slice 9 — validation warnings to surface on this container's header.
   * Populated either when a container's own id (e.g. an iterate) carries
   * a warning, or when collapse remapped a child's warning to this
   * ancestor. */
  warnings: readonly GraphWarning[];
  /**
   * Inferred state shape at this container's position (== shape after
   * the container exits). Empty string for containers the walker didn't
   * visit (shouldn't happen). Read by CSS via `data-state-shape` to
   * grey this container's drop anchor during an incompatible drag.
   */
  stateShape: string;
  /**
   * True when the current palette drag would land on THIS container if
   * the user released right now (the live drag-anchor preview). Toggles
   * `.graph-drop-target-active` so CSS can paint a subtle highlight.
   * Always false when no drag is in progress.
   */
  isDropTargetActive: boolean;
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
  // When the duplicate button renders next to the delete chip, the label
  // text needs to start further right or it sits underneath the chip on
  // hover. The delete chip alone is tolerated (existing behavior); a
  // SECOND chip pushes the overlap past readability. Memoize so the
  // shift recomputes only when the spec/container id changes.
  const labelLeftOffset = createMemo(() =>
    isRoundDuplicatable(props.container.id) ? WARNING_DOT_SIZE + 6 : 0,
  );
  return (
    <g
      class={`graph-container graph-container-${props.container.kind}`}
      classList={{ "graph-drop-target-active": props.isDropTargetActive }}
      tabindex={0}
      onKeyDown={(e) => {
        if (e.key === "Delete") {
          // Delete-only by design — Backspace is reserved for future
          // navigation use. Removes the container + every descendant
          // (`removeStep` is tree-aware in core/spec-mutations.ts).
          e.preventDefault();
          removeStepFromSpec(props.container.id);
        }
      }}
    >
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
          before the child leaves do. Carries `data-drop-anchor` so palette
          drops on the header route to this container — under the
          post-Slice-5 semantic (rescoped 2026-05-15), header drops mean
          "insert at start of this container's body," NOT "insert after
          the container in its parent." The handler interprets the anchor
          id by looking it up in `graph().containers`; lookups that hit a
          container route through `{ kind: "into-start", containerId }`.
          The outer `<g>` no longer carries `data-drop-anchor`, so body-
          area drops resolve via gutters/leaves only — the body-tile
          invariant on the gutter memo guarantees no body pixel is
          un-tiled, so the only place the container's anchor can fire is
          the header band (which is what we want). */}
      <rect
        class="graph-container-header"
        x={props.box.x}
        y={props.box.y}
        width={Math.max(0, props.box.w - CHEVRON_W)}
        height={HEADER_H}
        fill="transparent"
        data-drop-anchor={props.container.id}
        data-state-shape={props.stateShape}
        onPointerDown={(e) => props.onDragStart(e)}
        data-testid={`graph-container-header-${props.container.id}`}
      />
      <text
        class="graph-container-label"
        x={props.box.x + props.consts.CONTAINER_PAD + labelLeftOffset()}
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
      {/* Slice 9 — validation warning glyph in the header band, positioned
          to the LEFT of the chevron (and to the left of the iterate badge
          when one is present) so it never overlaps either affordance.
          Same shape + tooltip as the leaf indicator so users learn the
          glyph once. */}
      <Show when={props.warnings.length > 0}>
        {(() => {
          const hasIterateBadge =
            props.container.kind === "iterate" &&
            props.container.blockSpan !== undefined &&
            props.container.blockSpan > 1;
          // Right-edge reserve = chevron + (badge if present, with LABEL_RIGHT_GAP
          // breathing room). Matches the `labelTextLength` arithmetic above so
          // the warning glyph occupies the same "header right-side reserved
          // zone" as the badge, never the label area.
          const reserveRight =
            CHEVRON_W + LABEL_RIGHT_GAP + (hasIterateBadge ? ITERATE_BADGE_RESERVE_W : 0);
          const x = props.box.x + props.box.w - reserveRight - WARNING_DOT_SIZE;
          const y = props.box.y + (HEADER_H - WARNING_DOT_SIZE) / 2;
          return <WarningGlyph x={x} y={y} warnings={props.warnings} />;
        })()}
      </Show>
      {/* Delete affordance for the container — left edge of the header
          band, before the label. Removes the container + all descendants
          (`removeStep` is tree-aware via `transformParentArray`). Same
          hover-reveal pattern as the leaf's × button. */}
      <DeleteGlyph
        x={props.box.x + WARNING_DOT_INSET}
        y={props.box.y + (HEADER_H - WARNING_DOT_SIZE) / 2}
        stepId={props.container.id}
        onDelete={() => removeStepFromSpec(props.container.id)}
      />
      {/* Duplicate affordance for AES round groups. Sits immediately
          to the right of the delete chip, in the same row, hidden via
          the same hover-reveal CSS pattern. Gated by
          `isRoundDuplicatable` so the final round (no clean counterpart)
          doesn't render the button. */}
      <Show when={isRoundDuplicatable(props.container.id)}>
        <DuplicateGlyph
          x={props.box.x + WARNING_DOT_INSET + WARNING_DOT_SIZE + 4}
          y={props.box.y + (HEADER_H - WARNING_DOT_SIZE) / 2}
          containerId={props.container.id}
          onDuplicate={() => duplicateRoundInSpec(props.container.id)}
        />
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

const EdgePath = (props: {
  from: Box;
  to: Box;
  auxKey: string;
  kind: "aux" | "state";
  /**
   * True when this edge is iterate-feedback — a cross-iteration aux flow
   * collapsed into one canonical edge after the runtime's `:b{i}` strip.
   * Renderer signals this via a distinctive dashed style + label suffix
   * so the user can read "this loops to the next iteration" at a glance
   * rather than mistaking it for a backwards-pointing bug.
   *
   * Only meaningful when `kind === "aux"` — state edges are forward-only
   * by construction and the feedback predicate always returns false for
   * them. Defensive: even if a future bug stamps a state edge as
   * feedback, the dashed style is visual-only and doesn't affect dataflow.
   */
  isFeedback: boolean;
  /**
   * Identity key for the value-inspector store. The path's click
   * handler routes through this key so the panel below can look up
   * the value flowing through THIS edge at the current scrubber
   * position. Click-only — hover was dropped when the inspector
   * generalized to other element types.
   *
   * Why a string key (not the GraphEdge object): signals compare by
   * reference + value-equality. Strings are cheap to compare and cheap
   * to encode/decode at the boundary. The `view-value-inspector` store
   * holds the active key; the panel uses `decodeEdgeKey` only when it
   * needs the full GraphEdge to feed `lookupEdgeValue`.
   */
  edgeKey: string;
  /** True when this edge is the currently-selected inspector target —
   *  applies the `graph-edge-selected` halo class. */
  isSelected: boolean;
  /**
   * Port-spreading offset applied to the target attach x in the vertical
   * regime (replica above consumer). Computed at the parent `<For>` site
   * from `replicaTargetXOffset` so 3+ stacked replicas don't all converge
   * at the consumer's top-edge midpoint. Defaults to 0, so non-replica
   * edges and edges in single-source graphs render identically to pre-
   * port-spreading. Only the vertical regime (replica directly above
   * consumer) applies the offset — left-gutter replicas enter the
   * consumer's LEFT edge at distinct y values per replica, so there's no
   * convergence problem there and shifting x would push the arrow off
   * the consumer's vertical center.
   */
  targetXOffset?: number;
  /**
   * Horizontal shift applied to the SOURCE x of the path in the
   * vertical regime — `sx = fromCx + sourceXOffset`. Replica edges of
   * row k ≥ 1 receive a non-zero shift (alternating sign by row
   * parity, magnitude `ceil(k/2) × REPLICA_SOURCE_X_STEP`) so the
   * arrow's tail emerges from a non-centred point on the replica's
   * bottom edge. Clamped inside EdgePath so the start always lands
   * inside the source box. Defaults to 0.
   *
   * Only meaningful in the vertical regime; ignored in the horizontal
   * regime (replicas in horizontal regime use the left-gutter pattern,
   * which already spreads source y per row).
   */
  sourceXOffset?: number;
  /**
   * True when this edge originates from a fan-out replica. Two effects
   * in the vertical regime:
   *   1. Path is rendered as a straight `L` line instead of a cubic
   *      Bezier `C` — user explicitly asked for "straight lines with
   *      offset" so a passing-through-an-intervening-replica's-box
   *      arrow reads as a clear diagonal, not a swooping curve.
   *   2. A small `<circle>` start-dot is rendered at `(sx, sy)` so
   *      the eye can anchor "arrow starts at this dot" even when the
   *      line visually crosses a different replica's bounding box.
   * Non-replica edges (default `false`) keep the curve + no dot.
   */
  isReplicaEdge?: boolean;
}) => {
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
  // Returns both the SVG path `d` string and (for replica edges in the
  // vertical regime) the (x, y) position of the start-dot. Combined
  // into one memo so the geometry math runs once per change — the
  // start-dot lives at the same `(sx, sy)` the path starts from.
  const geom = createMemo<{ path: string; startDot: { x: number; y: number } | null }>(() => {
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
      // Source x: shifted by `sourceXOffset` for replica edges so the
      // arrow's tail emerges from a non-centred point on the source's
      // bottom edge. Clamped to the source's inner half-width minus a
      // 4 px margin so the start point always lands inside the source
      // box even on degenerate inputs.
      const rawSourceOffset = props.sourceXOffset ?? 0;
      const sourceOffsetCap = from.w / 2 - 4;
      const clampedSourceOffset = Math.max(
        -sourceOffsetCap,
        Math.min(sourceOffsetCap, rawSourceOffset),
      );
      const sx = fromCx + clampedSourceOffset;
      const sy = downward ? from.y + from.h : from.y;
      // Port-spreading: shift the target attach x by `targetXOffset`
      // (defaults to 0, so non-replica edges and single-source graphs
      // remain unaffected). Clamped to the consumer's inner half-width
      // minus a 4 px margin so the attach point always lands inside the
      // box even on degenerate inputs (huge `rowsTotal`, comically wide
      // PORT_GAP). With LEAF_W=132 and PORT_GAP=13, the typical bound
      // is ~62 — far more headroom than any realistic `rowsTotal` will
      // need.
      const rawOffset = props.targetXOffset ?? 0;
      const offsetCap = to.w / 2 - 4;
      const clampedOffset = Math.max(-offsetCap, Math.min(offsetCap, rawOffset));
      const tx = toCx + clampedOffset;
      const tEdge = downward ? to.y : to.y + to.h;
      const naturalGap = downward ? to.y - (from.y + from.h) : from.y - (to.y + to.h);
      // Clamp inset so even adjacent siblings (gap = STACK_GAP = 6) get a
      // monotonic, non-self-intersecting path.
      const inset = Math.max(0, Math.min(ARROW_INSET, naturalGap / 2));
      const ty = downward ? tEdge - inset : tEdge + inset;
      // Straight-line variant for replica edges (2026-05-16 pivot from
      // the curved-edge prototype): the user explicitly asked for
      // "straight lines with offset" so an arrow crossing through an
      // intervening replica's box reads as a clean diagonal, not a
      // swooping curve that adds visual noise. Combined with the
      // start-dot rendered below, the visual story is "this dot is
      // where the arrow starts; follow the line to where it ends."
      if (props.isReplicaEdge) {
        return {
          path: `M ${sx} ${sy} L ${tx} ${ty}`,
          startDot: { x: sx, y: sy },
        };
      }
      // Non-replica vertical-regime edge: keep the curve. Pull
      // magnitude proportional to the post-inset span; degenerates
      // to a straight line for very short edges.
      const span = Math.abs(ty - sy);
      const pull = Math.min(20, span * 0.5);
      const c1y = downward ? sy + pull : sy - pull;
      const c2y = downward ? ty - pull : ty + pull;
      return {
        path: `M ${sx} ${sy} C ${sx} ${c1y}, ${tx} ${c2y}, ${tx} ${ty}`,
        startDot: null,
      };
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
    return {
      path: `M ${sx} ${sy} C ${c1x} ${sy}, ${c2x} ${ty}, ${tx} ${ty}`,
      // Horizontal regime: no start-dot. Horizontal-regime replicas
      // are the "left-of-consumer" pattern from prior layout, which
      // already disambiguates by per-row source y; a dot at the right
      // edge would just clutter that case.
      startDot: null,
    };
  });
  // Keyboard handler mirrors the click so biome's a11y lint passes
  // (`useKeyWithClickEvents`). SVG `<path>` is non-focusable by default
  // — the handler will never actually fire in practice — but the rule
  // wants the affordance present in case a future cipher adds
  // `tabindex` to make edges keyboard-reachable.
  const handleKeyToggle = (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.stopPropagation();
      toggleSelectedEdge(props.edgeKey);
    }
  };
  return (
    // Two-layer render: the visible thin/dashed path on top (no pointer
    // events — it would otherwise compete with the wide hit path for
    // click detection), and a wide invisible hit path on top of it in
    // the SVG paint order that captures clicks on a fat 12px stroke.
    //
    // Why this matters: `.graph-edge-aux` renders at 1.5 px stroke and
    // `.graph-edge-state` at 2 px. SVG paths only react to events ON
    // their actual stroke, so a 2 px hit target is finicky to click
    // and worse at non-100% zooms. The 12 px transparent companion
    // gives users a comfortable hit zone (matches the slop most users
    // expect for "click the line"). Standard SVG idiom — same `d`,
    // `stroke="transparent"`, `pointer-events="stroke"`, `fill="none"`.
    // Drawn second so SVG paint order puts it on top of the visible
    // path; without that, browser hit-testing prefers the visible
    // path (smaller hit zone) when the cursor is dead-center.
    //
    // The visible path keeps its classes + selected halo styling because
    // `.graph-edge-selected`'s drop-shadow renders relative to the
    // visible stroke geometry; applying it to a transparent stroke
    // would render no shadow. The hit path also gets the data-edge-
    // key attribute because the component tests target `data-edge-
    // key` to locate click targets.
    <g>
      <path
        class={`graph-edge graph-edge-${props.kind}`}
        classList={{
          "graph-edge-feedback": props.isFeedback,
          "graph-edge-selected": props.isSelected,
        }}
        d={geom().path}
        marker-end={`url(#graph-arrow-${props.kind})`}
        pointer-events="none"
      />
      {/* Start-dot for replica edges: pins the visual origin of the
          arrow to a specific point on the source replica's bottom edge
          so the eye can disambiguate even when the straight diagonal
          line passes through an intervening replica's box. Painted
          AFTER the visible path so paint order puts it on top of the
          stroke; `pointer-events="none"` so clicks fall through to the
          hit path beneath it. */}
      <Show when={geom().startDot}>
        {(dot) => (
          <circle
            class={`graph-edge-start-dot graph-edge-start-dot-${props.kind}`}
            classList={{
              "graph-edge-feedback": props.isFeedback,
              "graph-edge-selected": props.isSelected,
            }}
            cx={dot().x}
            cy={dot().y}
            r={3}
            pointer-events="none"
          />
        )}
      </Show>
      <path
        class="graph-edge-hit"
        d={geom().path}
        data-edge-key={props.edgeKey}
        onClick={(e) => {
          // stopPropagation so the click doesn't bubble up to the
          // canvas (which would otherwise treat empty-area clicks as
          // drag-cancel or future canvas-level handlers).
          e.stopPropagation();
          toggleSelectedEdge(props.edgeKey);
        }}
        onKeyDown={handleKeyToggle}
      >
        <title>
          {props.auxKey}
          {props.isFeedback ? " — feedback (next iteration)" : ""}
        </title>
      </path>
    </g>
  );
};

/**
 * Maximum entries to render before truncating to "… N more" for a value
 * that resolves to `readonly State[]` (e.g. the iterate's `blocksFromAux`
 * shown on the boundary edge into a non-collapsed iterate). Picked to
 * match Slice 6's block-chip cap (6) so the inspector and the canvas
 * tell the same story about how much detail is shown.
 */
const INSPECTOR_ARRAY_PREVIEW_CAP = 6;

/**
 * Render an `AuxValue` (or `State`) as a single line of text suitable
 * for the inspector panel. Bytes-y values flow through `formatBytes`
 * with the active byte format. Arrays show up to `INSPECTOR_ARRAY_PREVIEW_CAP`
 * entries followed by "… N more" — typical case is "first 6 blocks of
 * 8" or similar, matching the chip cap visually.
 *
 * Why one line: the panel sits below the replication panel above the
 * SVG, so vertical real estate is precious. A pre-formatted plain
 * string lets us reuse the existing `.graph-value-inspector-value-row`
 * styling without growing per-shape branches in the JSX.
 */
const formatAuxValueOneline = (value: AuxValue, fmt: ByteFormat): string => {
  // Array of States (e.g. blocksFromAux / outBlocksAux). Slice + ellipsis.
  if (Array.isArray(value)) {
    const arr = value as readonly State[];
    const visible = arr.slice(0, INSPECTOR_ARRAY_PREVIEW_CAP);
    const formatted = visible.map((s) => formatStateOneline(s, fmt));
    const tail =
      arr.length > INSPECTOR_ARRAY_PREVIEW_CAP
        ? `, … ${arr.length - INSPECTOR_ARRAY_PREVIEW_CAP} more`
        : "";
    return `[ ${formatted.join(", ")}${tail} ]`;
  }
  // Plain Uint8Array (e.g. round-key aux). Render through formatBytes.
  if (value instanceof Uint8Array) {
    return formatBytes(value, fmt);
  }
  // Number / bigint (e.g. blockCount). String-ify directly.
  if (typeof value === "number" || typeof value === "bigint") {
    return value.toString();
  }
  // State variant — discriminate on shape. Narrowing has eliminated the
  // array/Uint8Array/number/bigint branches above, so the residual type
  // is the State union; cast to satisfy TS without changing semantics.
  return formatStateOneline(value as State, fmt);
};

const formatStateOneline = (state: State, fmt: ByteFormat): string => {
  switch (state.shape) {
    case "bytes":
      return formatBytes(state.bytes, fmt);
    case "matrix4x4-bytes":
      return formatBytes(state.bytes, fmt);
    case "bitvec":
      // No bit-level renderer yet — show the underlying packed bytes as
      // hex regardless of fmt. Once a cipher actually exercises bitvec
      // state we can add a dedicated bit-string formatter.
      return formatBytes(state.bits, "hex");
    case "bigint":
      return state.value.toString();
  }
};

/**
 * Body of the value-inspector panel. Pulled out as a separate component
 * because the value-lookup memo + the kind-badge logic add visual
 * weight; threading the dependencies as props keeps the parent JSX
 * readable without inlining 50 lines of inspector code.
 *
 * Reactivity dependencies:
 *   - `selectedTarget` — the user's currently-selected edge or node
 *   - `frameIndex` — current scrubber position drives block-aware lookup
 *   - `version` — re-run replaces the trace; without this dep, the
 *     panel would render against a stale trace after a param edit
 *   - `byteFormat` — value formatting is format-aware
 *
 * Missing any of those produces a stale panel; pinning the list here
 * (and matching it in the memo body) is the discipline check.
 *
 * Dispatch: the memo branches on `selectedTarget().kind`:
 *   - `"edge"` → `lookupEdgeValue` with the resolved GraphEdge.
 *   - `"node"` → `lookupNodeValue` with the raw node id.
 *
 * Identity row also branches: edges show `from → to`; nodes show just
 * the id (with no arrow). Kind-badge label is shape-derived (state /
 * block-payload / aux: <key> / endpoint / no-trace / no value).
 */
const ValueInspectorBody = (props: {
  selectedTarget: () => ValueInspectorTarget | null;
  edges: () => readonly GraphEdge[];
  spec: () => import("@/core/types").CipherSpec;
  frameIndex: () => number;
  version: () => number;
  byteFormat: () => ByteFormat;
}) => {
  // Resolve an edge-kind target back to a GraphEdge by looking it up in
  // the current graph (rather than decoding the key directly). The
  // current graph is the post-replication, post-collapse, post-chip-
  // expansion graph the renderer is showing — so the edge we find is
  // the same identity the user clicked, including any synthetic chip
  // endpoints. Decoding the key without this lookup would also work
  // (the format round-trips), but going through `edges()` makes the
  // inspector automatically degrade to "missing" if a spec change
  // retired the selected edge between click and render.
  const activeEdge = createMemo<GraphEdge | null>(() => {
    const t = props.selectedTarget();
    if (t === null || t.kind !== "edge") return null;
    for (const e of props.edges()) {
      if (encodeEdgeKey(e) === t.key) return e;
    }
    return null;
  });

  const lookup = createMemo<EdgeValueLookup | null>(() => {
    // Tracked deps so the memo invalidates on every change that could
    // affect the rendered value. The block-aware lookup needs the
    // current frame's blockIndex; the trace lives outside Solid
    // (perf), so we read it via `getTrace()` with `version()` as the
    // invalidation trigger.
    void props.version();
    const trace = getTrace();
    const t = props.selectedTarget();
    if (t === null) return null;
    const idx = props.frameIndex();
    const currentBlockIndex = trace !== null ? trace.frames[idx]?.blockIndex : undefined;
    if (t.kind === "edge") {
      const edge = activeEdge();
      if (edge === null) return null;
      return lookupEdgeValue(edge, props.spec(), trace, currentBlockIndex);
    }
    return lookupNodeValue(t.id, props.spec(), trace, currentBlockIndex);
  });

  // Identity-row branching: edges show `from → to`; nodes show just
  // their id. The aux key for the kind-badge is taken from the lookup
  // result's `auxKey` field (it's `"state"` for state-derived rows and
  // the real key for aux rows; we use it directly via `kindBadgeText`).
  return (
    <div class="graph-value-inspector-body" data-testid="value-inspector-body">
      <Show
        when={props.selectedTarget() !== null}
        fallback={
          <div class="graph-value-inspector-empty">Click an edge or node to see its value.</div>
        }
      >
        {(_present) => {
          const result = () => lookup();
          // Memo over `selectedTarget()` to get a stable string for the
          // node-identity span. Returns "" when the target is an edge —
          // the edge branch renders its own from→to spans.
          const nodeId = createMemo(() => {
            const t = props.selectedTarget();
            return t !== null && t.kind === "node" ? t.id : "";
          });
          return (
            <>
              <div class="graph-value-inspector-identity">
                <Show
                  when={activeEdge()}
                  fallback={
                    // Node identity: single span, no arrow. For chips, the
                    // id is the full synthetic form (`ecb-blocks@block0`);
                    // for endpoint pills it's the `__cipher_*__` constant.
                    <span class="graph-value-inspector-from" title={nodeId()}>
                      {nodeId()}
                    </span>
                  }
                >
                  {(edge) => (
                    <>
                      <span class="graph-value-inspector-from" title={edge().from}>
                        {edge().from}
                      </span>
                      <span class="graph-value-inspector-arrow" aria-hidden="true">
                        →
                      </span>
                      <span class="graph-value-inspector-to" title={edge().to}>
                        {edge().to}
                      </span>
                    </>
                  )}
                </Show>
              </div>
              <Show when={result()}>
                {(r) => (
                  <>
                    <div class="graph-value-inspector-kind-row">
                      <span
                        class={`graph-value-inspector-kind-badge graph-value-inspector-kind-${r().status === "value" ? r().status : "info"}`}
                      >
                        {kindBadgeText(r())}
                      </span>
                    </div>
                    <div class="graph-value-inspector-value-row">
                      {valueRowText(r(), props.byteFormat())}
                    </div>
                  </>
                )}
              </Show>
            </>
          );
        }}
      </Show>
    </div>
  );
};

/** Compute the kind-badge label for an inspector row. Uses the lookup
 *  result's `auxKey` directly so the function works for both edge and
 *  node selections (which don't carry a GraphEdge). */
const kindBadgeText = (r: EdgeValueLookup): string => {
  if (r.status === "endpoint") {
    return r.endpointSide === "input" ? "input pill" : "output pill";
  }
  if (r.status === "no-trace") return "no trace";
  if (r.status === "missing") return "no value";
  // r.status === "value"
  const blockSuffix = r.blockIndex !== undefined ? ` (block ${r.blockIndex})` : "";
  if (r.displayKind === "state") return `state${blockSuffix}`;
  if (r.displayKind === "block-payload") return `block payload${blockSuffix}`;
  return `aux: ${r.auxKey}${blockSuffix}`;
};

/** Render the value-row content for an inspector row. Returns a string;
 *  rich rendering (matrix grid etc.) is intentionally not part of v1. */
const valueRowText = (r: EdgeValueLookup, fmt: ByteFormat): string => {
  switch (r.status) {
    case "endpoint":
      return r.label;
    case "no-trace":
      return "Run the cipher to see values.";
    case "missing":
      return r.reason;
    case "value":
      return formatAuxValueOneline(r.value, fmt);
  }
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
