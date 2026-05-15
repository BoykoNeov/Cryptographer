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

import {
  type CipherGraph,
  type ContainerNode,
  type GraphEdge,
  type GraphNode,
  type GraphWarning,
  buildIterateFeedbackPredicate,
  collapseGraph,
  deriveAuxGraph,
  replicateHighFanoutSources,
  validateGraph,
} from "@/core/graph";
import { inferShapesAtAnchors, validateShapes } from "@/core/spec-shapes";
import type { StepNode } from "@/core/types";
import { For, Show, createEffect, createMemo, createSignal, on } from "solid-js";
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
import { getTrace, setSelectedStepId, useTraceVersion } from "../stores/trace";
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
};

const EMPTY_REPLICA_PLACEMENT: ReplicaPlacement = {
  isReplica: new Set(),
  consumerOf: new Map(),
};

/**
 * Build the replica → consumer map from the graph. The replica's
 * outgoing aux edge points at its consumer (every replica has exactly
 * one — that's the point of replication). Using the edge list (not the
 * `${src}@->${consumer}` id format) keeps the layout decoupled from
 * `graph.ts`'s replica-id convention.
 */
const buildReplicaPlacement = (graph: CipherGraph): ReplicaPlacement => {
  const isReplica = new Set<string>();
  const consumerOf = new Map<string, string>();
  for (const n of graph.nodes) {
    if (n.replicaOf !== undefined) isReplica.add(n.stepId);
  }
  if (isReplica.size === 0) return EMPTY_REPLICA_PLACEMENT;
  for (const e of graph.edges) {
    if (e.kind !== "aux") continue;
    if (isReplica.has(e.from)) consumerOf.set(e.from, e.to);
  }
  return { isReplica, consumerOf };
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
    const liftH = liftedReplicas.length > 0 ? consts.LEAF_H + consts.STACK_GAP : 0;

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
    // child) directly above their consumer in the column. The liftH
    // shift on innerY above guarantees this y lands inside the group's
    // padded inner area, just below the header.
    //
    // Per-consumer index counter — see `layoutRoot` for the full rationale.
    // Multiple sources targeting the same consumer (e.g. dual `always`
    // replication overrides) would otherwise stack at identical
    // coordinates; step subsequent replicas RIGHT by LEAF_W + FLOW_GAP.
    const liftedReplicaIndexByConsumer = new Map<string, number>();
    for (const replicaId of liftedReplicas) {
      const consumerId = replicas.consumerOf.get(replicaId);
      if (consumerId === undefined) continue;
      const consumerBox = out.get(consumerId);
      if (!consumerBox) continue;
      const idx = liftedReplicaIndexByConsumer.get(consumerId) ?? 0;
      liftedReplicaIndexByConsumer.set(consumerId, idx + 1);
      out.set(replicaId, {
        x: consumerBox.x + idx * (consts.LEAF_W + consts.FLOW_GAP),
        y: consumerBox.y - consts.LEAF_H - consts.STACK_GAP,
        w: consts.LEAF_W,
        h: consts.LEAF_H,
      });
    }

    const columnW = Math.max(maxChildW, consts.LEAF_W);
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
  const replicaLiftH = hasIterateReplicas ? consts.LEAF_H + consts.STACK_GAP : 0;

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
  // lifted innerY guarantees consumer.y - LEAF_H - STACK_GAP lands at
  // the OLD innerY (the natural top of the inner content), which is
  // inside the container's box.
  //
  // Per-consumer index counter — see `layoutRoot` for the full rationale.
  // Multiple sources targeting the same consumer (e.g. dual `always`
  // replication overrides) would otherwise stack at identical
  // coordinates; step subsequent replicas RIGHT by LEAF_W + FLOW_GAP.
  const iterateReplicaIndexByConsumer = new Map<string, number>();
  for (const childId of container.childIds) {
    if (!replicas.isReplica.has(childId)) continue;
    const consumerId = replicas.consumerOf.get(childId);
    if (consumerId === undefined) continue;
    const consumerBox = out.get(consumerId);
    if (!consumerBox) continue;
    const idx = iterateReplicaIndexByConsumer.get(consumerId) ?? 0;
    iterateReplicaIndexByConsumer.set(consumerId, idx + 1);
    const replicaY = consumerBox.y - consts.LEAF_H - consts.STACK_GAP;
    out.set(childId, {
      x: consumerBox.x + idx * (consts.LEAF_W + consts.FLOW_GAP),
      y: replicaY,
      w: consts.LEAF_W,
      h: consts.LEAF_H,
    });
  }

  const w = lastChildRight - startX + consts.CONTAINER_PAD;
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
  const hasRootReplicas = graph.rootIds.some((id) => replicas.isReplica.has(id));
  const hasAuxOnlyRoots = graph.rootIds.some((id) => auxOnlyRootIds.has(id));
  const needsSpineLift = hasRootReplicas || hasAuxOnlyRoots;
  const rootReplicaLiftH = needsSpineLift ? consts.LEAF_H + consts.STACK_GAP : 0;
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
  // shift above guarantees `consumer.y - LEAF_H - STACK_GAP === CANVAS_MARGIN`
  // for non-pinned consumers, so the replica row sits flush against the
  // top margin (no negative-y boxes; canvas dimensions don't need
  // re-extension).
  //
  // Per-consumer index counter: multiple distinct sources can target the
  // same consumer (e.g. setting both `compute-block-count` and
  // `split-blocks` to "always" in the replication-overrides panel yields
  // two replicas pointing at the iterate). Without the counter the second
  // replica lands directly on top of the first — same x, same y — and only
  // one is visible / clickable. We step each subsequent replica RIGHT by
  // LEAF_W + FLOW_GAP so they tile horizontally above the consumer.
  // The same pattern repeats in `layoutNode`'s group + iterate branches —
  // three sites, one fix each, because each layout pass owns its own
  // replica-placement loop.
  const rootReplicaIndexByConsumer = new Map<string, number>();
  for (const id of graph.rootIds) {
    if (!replicas.isReplica.has(id)) continue;
    const consumerId = replicas.consumerOf.get(id);
    if (consumerId === undefined) continue;
    const consumerBox = boxes.get(consumerId);
    if (!consumerBox) continue;
    const idx = rootReplicaIndexByConsumer.get(consumerId) ?? 0;
    rootReplicaIndexByConsumer.set(consumerId, idx + 1);
    const replicaY = consumerBox.y - consts.LEAF_H - consts.STACK_GAP;
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
    const consumerContainer = containersById.get(consumerId);
    const firstNonReplicaChildId =
      consumerContainer?.kind === "iterate"
        ? consumerContainer.childIds.find((cid) => !replicas.isReplica.has(cid))
        : undefined;
    const firstChildBox =
      firstNonReplicaChildId !== undefined ? boxes.get(firstNonReplicaChildId) : undefined;
    const anchorX = firstChildBox?.x ?? consumerBox.x;
    boxes.set(id, {
      x: anchorX + idx * (consts.LEAF_W + consts.FLOW_GAP),
      y: replicaY,
      w: consts.LEAF_W,
      h: consts.LEAF_H,
    });
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
 * the upcoming Slice 4 edge inspector both read `edge.to` to surface
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

  /** Apply optional fanout replication on top of the collapsed graph.
   * Master-switch semantic: when the global toggle is off, NO replicas
   * appear — even if the user has per-source `"always"` overrides set.
   * The override panel below is hidden in that case so the user doesn't
   * wonder why their override isn't taking effect.
   */
  const replicatedGraph = createMemo<CipherGraph>(() =>
    replicate()
      ? replicateHighFanoutSources(collapsedGraph(), replicationThreshold(), replicationModes())
      : collapsedGraph(),
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
    // Resolve the same anchor the drop handler would use — `closest`
    // walks up from the element under the cursor looking for the nearest
    // `data-drop-anchor`. Null when the cursor is in the canvas gap
    // (drop would root-append). Update the signal continuously so the
    // highlight tracks the cursor in real time.
    const target = e.target as Element | null;
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
  };

  const handleDrop = (e: DragEvent): void => {
    e.preventDefault();
    setDragOverActive(false);
    setDragOverAnchorId(null);
    if (!e.dataTransfer) return;
    // Prefer the custom MIME (palette-authored); fall back to text/plain
    // for browsers that strip non-standard MIMEs on DnD payloads.
    const stepType =
      e.dataTransfer.getData(STEP_TYPE_DRAG_MIME) || e.dataTransfer.getData("text/plain");
    if (!stepType || !registry.has(stepType)) return;
    // Walk up from the drop target looking for the nearest `data-drop-anchor`
    // attribute. `closest` returns the element itself if it matches, so a
    // drop directly on a `<g class="graph-leaf">` finds itself. Replicas
    // carry their `clickTargetId` (source's stepId), so the anchor is
    // always a real spec id.
    const target = e.target as Element | null;
    const anchored = target?.closest?.("[data-drop-anchor]") ?? null;
    const anchorId = anchored?.getAttribute("data-drop-anchor") ?? null;
    if (anchorId !== null && anchorId.length > 0) {
      insertStepIntoSpec(stepType, { kind: "after", stepId: anchorId });
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
      // SVG viewBox is 1:1 with rendered width/height, so client-px delta
      // maps directly onto SVG-unit delta.
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
      const newX = Math.max(0, startBoxX + dx);
      const newY = Math.max(0, startBoxY + dy);
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

  return (
    <div class="graph-view-layout" data-testid="graph-view-layout">
      {/* Slice 8 — step palette. Lives as a left sidebar inside the graph
          view layout so it's only visible when the user is in graph mode.
          Drags from the palette dispatch DataTransfer payloads that the
          canvas's drop handlers below pick up. Doesn't subscribe to spec/
          trace signals — the registry it lists is static after module load. */}
      <StepPalette />
      <div
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
                <For each={replicationSources()}>
                  {(src) => {
                    const currentMode = createMemo<"auto" | "always" | "never">(() => {
                      const m = replicationModes()[src.id];
                      return m ?? "auto";
                    });
                    return (
                      <div class="graph-replication-row" data-testid={`replication-row-${src.id}`}>
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
              </Show>
            </div>
          </Show>
        </div>
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
                  return (
                    <Show when={epBox()}>
                      {(b) => <EndpointPill box={b()} side={side} label={node.label} />}
                    </Show>
                  );
                }
                const box = createMemo(() => layout().boxes.get(node.stepId));
                const isInsideIterate = node.containerPath.some((id) => {
                  const c = containersById().get(id);
                  return c?.kind === "iterate";
                });
                const isRootLevel = node.containerPath.length === 0;
                const isReplica = node.replicaOf !== undefined;
                // Replicas route clicks through `replicaOf` so the scrubber
                // lands on the SOURCE's frame, not on the replica's synthetic
                // id (which has no matching trace frame). Replicas are also
                // never draggable — they're auto-placed visual references.
                const clickTargetId = node.replicaOf ?? node.stepId;
                // exactOptionalPropertyTypes is on, so we conditionally spread
                // blockSpan rather than passing `undefined` as a real value.
                const blockSpanProps =
                  isInsideIterate && node.blockSpan !== undefined
                    ? { blockSpan: node.blockSpan }
                    : {};
                // Conditional spread for the drag handler — only present on
                // root-level leaves AND not replicas (replicas are auto-placed).
                const dragProps =
                  isRootLevel && !isReplica
                    ? {
                        onPointerDown: (e: PointerEvent) =>
                          startNodeDrag(node.stepId, e, () => handleLeafClick(clickTargetId)),
                      }
                    : {};
                const leafWarnings = createMemo(() => warningsByVisibleId().get(node.stepId) ?? []);
                return (
                  <Show when={box()}>
                    {(b) => (
                      <LeafRect
                        stepId={node.stepId}
                        label={shortLeafLabel(clickTargetId)}
                        stepType={node.stepType}
                        box={b()}
                        draggable={isRootLevel && !isReplica}
                        isReplica={isReplica}
                        dropAnchorId={clickTargetId}
                        // Reactive: the JSX expression re-evaluates when
                        // dragOverAnchorId() changes, and Solid forwards
                        // the new prop value through to LeafRect — which
                        // toggles `.graph-drop-target-active` accordingly.
                        isDropTargetActive={dragOverAnchorId() === clickTargetId}
                        {...blockSpanProps}
                        {...dragProps}
                        onClick={() => handleLeafClick(clickTargetId)}
                        warnings={leafWarnings()}
                        stateShape={shapesByAnchor().get(clickTargetId) ?? ""}
                      />
                    )}
                  </Show>
                );
              }}
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
      classList={{ "graph-drop-target-active": props.isDropTargetActive }}
      data-drop-anchor={props.dropAnchorId}
      data-state-shape={props.stateShape}
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
 * Deliberately NO affordances:
 *   - no `data-drop-anchor` (palette drops can't target the pill)
 *   - no `tabindex` (not in keyboard focus order; nothing to focus on)
 *   - no `onClick` (no trace frame to scrub to)
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
}) => (
  <g class={`graph-endpoint-pill graph-endpoint-${props.side}`}>
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
      data-drop-anchor={props.container.id}
      data-state-shape={props.stateShape}
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
      classList={{ "graph-edge-feedback": props.isFeedback }}
      d={d()}
      marker-end={`url(#graph-arrow-${props.kind})`}
    >
      <title>
        {props.auxKey}
        {props.isFeedback ? " — feedback (next iteration)" : ""}
      </title>
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
