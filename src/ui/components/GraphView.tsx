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

import { arxDoubleRoundsById, arxRoundNeverModes } from "@/core/arx-group";
import { arxDoubleRoundPlacement } from "@/core/arx-round-layout";
import type { ArxDoubleRoundShape } from "@/core/arx-round-shape";
import {
  type CellProvenanceSummary,
  summarizeCellProvenance,
} from "@/core/cell-provenance-summary";
import { curatedDefaultFor, mergeLayoutSpecs, scaleCuratedLayout } from "@/core/default-layouts";
import {
  type EdgeValueLookup,
  lookupEdgeValue,
  lookupNodeValue,
  resolveNodeFrame,
} from "@/core/edge-value-lookup";
import {
  feistelRoundPlacement,
  feistelRoundsStackVertically,
  feistelSwapWires,
} from "@/core/feistel-layout";
import {
  type FeistelRoundShape,
  analyzeFeistelRound,
  feistelValueLabels,
} from "@/core/feistel-shape";
import { type ByteFormat, formatBytes } from "@/core/format";
import {
  type CipherGraph,
  type ContainerNode,
  type EdgeBundle,
  type GraphEdge,
  type GraphNode,
  type GraphWarning,
  PORT_FLOW_AUX_KEY,
  buildIterateFeedbackPredicate,
  bundleEdges,
  bundleKeyFor,
  collapseGraph,
  deriveAuxGraph,
  expandCollapsedIterates,
  isEndpointId,
  replicateHighFanoutSources,
  validateGraph,
} from "@/core/graph";
import { resolvePortMap } from "@/core/port-projection";
import { type LegalSource, legalSourcesForInput } from "@/core/port-sources";
import { allColorableSources, assignSourceColors } from "@/core/source-colors";
import {
  STROKE_STYLE_CATALOGUE,
  type StrokeStyle,
  assignSourceStrokes,
  strokeStyleByName,
} from "@/core/source-strokes";
import {
  getAllContainerIds,
  getDefaultCollapsedContainers,
  getEffectiveCollapsedSet,
} from "@/core/spec-defaults";
import {
  type CompositeInsertAnchor,
  captureCompositeFromGroup,
  findStep,
} from "@/core/spec-mutations";
import { inferShapesAtAnchors, validateShapes } from "@/core/spec-shapes";
import { twofishRoundPlacement } from "@/core/twofish-layout";
import { type TwofishRoundShape, analyzeTwofishRound } from "@/core/twofish-shape";
import type { AuxValue, State, StepNode } from "@/core/types";
import { For, Show, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { hasNarrationFn } from "../narration/registry";
import { isAsymmetric, isHash, useAlgorithm } from "../stores/cipher";
import { getComposite, saveComposite } from "../stores/composites";
import {
  isCuratedLayoutSuppressed,
  suppressCuratedLayout,
  unsuppressCuratedLayout,
} from "../stores/curated-layout-suppress";
import { beginLayoutGesture, cancelLayoutGesture, endLayoutGesture } from "../stores/edit-history";
import { useByteFormat } from "../stores/format";
import {
  clearNodePosition,
  clearRelativePosition,
  collapseAllContainers,
  expandAllContainers,
  hasUserLayout,
  setLayoutForSpec,
  setNodePosition,
  setRelativePosition,
  setReplicationMode,
  setSourceStroke,
  toggleCollapse,
  useLayoutMap,
} from "../stores/layout";
import { isOffsetsEnabledForLayout } from "../stores/offsets-hatch";
import { registry } from "../stores/registry";
import {
  bindPortInSpec,
  duplicateRoundInSpec,
  insertCompositeIntoSpec,
  insertStepIntoSpec,
  isRoundDuplicatable,
  removeStepFromSpec,
  useMode,
  useSpec,
} from "../stores/spec";
import { getTrace, setSelectedStepId, useFrameIndex, useTraceVersion } from "../stores/trace";
import { isTwofishCanonicalEnabledForLayout } from "../stores/twofish-canonical-hatch";
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
  useReplicationUserToggledThisSession,
} from "../stores/view-replication";
import {
  COLOR_THRESHOLD_MAX,
  COLOR_THRESHOLD_MIN,
  DEFAULT_COLOR_THRESHOLD,
  clearAllSourceColorOverrides,
  clearSourceColorOverride,
  setColorThreshold,
  setSourceColorOverride,
  toggleColorsPanelOpen,
  toggleIncludeSingleSources,
  toggleSourceColoringEnabled,
  useColorThreshold,
  useColorsPanelOpen,
  useIncludeSingleSources,
  useManualSourceColors,
  useSourceColoringEnabled,
} from "../stores/view-source-colors";
import {
  DEFAULT_STROKE_THRESHOLD,
  STROKE_THRESHOLD_MAX,
  STROKE_THRESHOLD_MIN,
  setStrokeThreshold,
  toggleSourceStrokeStylingEnabled,
  useSourceStrokeStylingEnabled,
  useStrokeThreshold,
} from "../stores/view-source-strokes";
import {
  type ValueInspectorTarget,
  clearSelectedTarget,
  decodeBundleKey,
  encodeEdgeKey,
  isBundleSelected,
  isEdgeSelected,
  isNodeSelected,
  setActiveBundleAuxKey,
  toggleInspectorPanelOpen,
  toggleSelectedEdge,
  toggleSelectedNode,
  useActiveBundleAuxKey,
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
import { disarmPort, toggleArmPort, useArmedPort } from "../stores/wiring";
import { CellProvenanceView } from "./CellProvenanceView";
import { GraphHelpModal } from "./GraphHelpModal";
import { PortFlowView } from "./PortFlowView";
import { StepDescription, resolveStepDoc } from "./StepDescription";
import { StepNarration } from "./StepNarration";
import {
  COMPOSITE_DRAG_MIME,
  STEP_TYPE_DRAG_MIME,
  StepPalette,
  useActiveDragStepType,
} from "./StepPalette";

/**
 * Shared empty map for the source-color memo's OFF / no-data branch.
 * Pre-allocated at module scope so the `effectiveSourceColors` memo
 * doesn't churn the GC creating a new empty map on every off-state
 * recomputation (the master toggle defaulting ON means most users
 * never hit this branch, but it's the canonical no-op identity for
 * tests + the fall-through path).
 */
const EMPTY_COLOR_MAP: ReadonlyMap<string, string> = new Map();

/**
 * Shared empty map for the source-*stroke* memo's OFF / no-data branch.
 * Same GC-churn rationale as `EMPTY_COLOR_MAP`, but this branch is the
 * COMMON case: the stroke master toggle ships OFF (see
 * `view-source-strokes.ts`), so most sessions read this identity.
 */
const EMPTY_STROKE_MAP: ReadonlyMap<string, string> = new Map();

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
/** Base (1.0×) vertical gap between siblings stacked inside a group.
 *  History: 6 → 12 (2026-05-19) → 60 (2026-05-27).
 *  The 6 → 12 (2×) bump gave the four leaves stacked inside each AES
 *  round group (SubBytes → ShiftRows → MixColumns → AddRoundKey) — and
 *  the three inside the final round — visible breathing room over the
 *  pre-bump 6 px, where consecutive leaves sat essentially flush and
 *  the four-row stack read as a single solid block.
 *  The 12 → 60 (5×) bump on 2026-05-27 was requested for "much more
 *  breathing room inside expanded round/group bodies" — the post-2× gap
 *  still read tight once the AES round groups + SHA-256 expanded
 *  message-schedule rounds shared a canvas. With 60 px gaps a 4-leaf
 *  round group now spans 4 × 28 + 3 × 60 = 292 px tall (was 148 px),
 *  but the SVG viewBox auto-sizes from layout (`canvasH = maxBottom +
 *  CANVAS_MARGIN`) so nothing clips.
 *  STACK_GAP is reused at one site beyond plain group stacking
 *  (the `innerY` advance in `layoutNode`'s group branch); see comments
 *  there if a future bump runs into edge cases. */
const BASE_STACK_GAP = 60;
/** Base (1.0×) horizontal gap between siblings flowing inside an iterate body / root.
 *  History: 16 → 24 (2026-05-16) → 36 (2026-05-19) → 72 (2026-05-27).
 *  16 → 24 (2026-05-16) added breathing room on the collapsed-iterate
 *  chip row — multiple chips + aux replicas above were cramping on the
 *  AES-128 ECB canvas. 24 → 36 (2026-05-19) followed a user report that
 *  the CBC iterate body's chip row still felt crowded — 13 sibling
 *  boxes (cbc-xor + initial.add-round-key + 9 rounds + final round +
 *  cbc-snapshot) at 132 px wide ran flush, reading as a wall rather
 *  than a clearly-spaced sequence.
 *  36 → 72 (2×, 2026-05-27) — user requested "much more breathing room"
 *  between flowing leaves across the root and inside iterate bodies
 *  (AES round chips, SHA-256 message-schedule chips). The doubled gap
 *  trades horizontal canvas width for clearly separated chip identities;
 *  the SVG viewBox auto-sizes (`canvasW = maxRight + CANVAS_MARGIN`) so
 *  the wider layout cannot escape the canvas.
 *  Affects both root-level flow AND iterate body flow (one constant,
 *  used both places). */
const BASE_FLOW_GAP = 72;
/** Base (1.0×) padding inside a container (group or iterate) box. */
const BASE_CONTAINER_PAD = 10;
/**
 * Direct-child count at/above which an EXPANDED iterate reserves a second
 * inner-region of empty space below its body (see the iterate branch of
 * `layoutNode`). A structural heuristic — NOT a spec id — for "this is a
 * large-bodied fold the user hand-arranges," so it needs no per-spec plumbing
 * in the pure layout function. Today the only iterate that clears it is
 * SHA-256's per-block compression fold (~76 children); AES ECB/CBC iterates
 * wrap a single round-body group (1-few children) and stay snug. NOT density-
 * scaled — it's a count, not a length.
 */
const ITERATE_HEADROOM_MIN_CHILDREN = 8;
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
 * `consumerPortOffset`'s slot ordering at the consumer head (slots are
 * assigned in row order; see `ConsumerPortAssignment` doc) so each
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
const BASE_REPLICA_LIFT_GAP = 36;
/**
 * Base (1.0×) vertical gap BETWEEN two stacked replica chips above the
 * same consumer. Distinct from `FLOW_GAP` (which governs sibling
 * stacking inside groups) so we can tune replica spacing without
 * disturbing the rest of the layout. Bumped from FLOW_GAP=24 to 48 on
 * 2026-05-17 after the user reported "the arrow counter is almost the
 * same size as the space between the replicates" — the ×N pill is
 * ~32–40 px wide, so a 24 px gap made adjacent pills crowd each other.
 * 48 px gives the pills clear separation while keeping the column of
 * replicas readable as one stack.
 */
const BASE_REPLICA_STACK_GAP = 48;
/** Height of the container's header band (label + optional ×N chip). Fixed. */
const HEADER_H = 22;
/**
 * Outer margin of the SVG canvas. Drives both the top and left initial
 * offset for all root content. Tuned across two rounds on 2026-05-17 in
 * response to user feedback during the arrow-bundling smoke: first
 * bump 24 → 44 ("all items in the canvas should spawn initially a
 * little bit lower"), then 44 → 60 ("more space to the top" after the
 * first smoke wasn't enough). The higher value keeps the canvas chrome
 * (toolbar, replication panel) from feeling cramped against the
 * topmost row of nodes.
 */
const CANVAS_MARGIN = 60;
/**
 * Extra scroll headroom appended to the RIGHT and BOTTOM of the canvas beyond
 * the leading `CANVAS_MARGIN` origin (2026-07-12, user: "give more vertical
 * and horizontal space… the bottom is hard to access and read even when
 * scrolled maximally down"). Purely trailing padding: the last row/column of
 * nodes is no longer flush against the scroll boundary, so the user can scroll
 * the bottommost content up into the middle of the viewport to read it — and,
 * because the value inspector floats sticky at the TOP-LEFT, the extra room
 * lets any node be panned out from under it. Bottom gets more than right
 * because the sticky toolbar/inspector band eats top viewport height, so the
 * bottom needs the larger reserve to clear it. Kept SEPARATE from
 * `CANVAS_MARGIN` so the layout ORIGIN (which the replica-gutter / drag /
 * label-truncation tests pin to 60) is untouched — only the trailing extent
 * grows, and every relative canvasW/H assertion (density ordering, feistel /
 * twofish `withMap === without`) still holds since both sides gain the pad.
 */
const CANVAS_TRAILING_PAD_RIGHT = 120;
const CANVAS_TRAILING_PAD_BOTTOM = 180;
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
  /**
   * Vertical gap between two stacked replica chips above the same
   * consumer. Distinct from `FLOW_GAP` so we can tune replica-stack
   * density without disturbing the rest of the layout. See
   * `BASE_REPLICA_STACK_GAP`.
   */
  readonly REPLICA_STACK_GAP: number;
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
    REPLICA_STACK_GAP: Math.round(BASE_REPLICA_STACK_GAP * scale),
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
 * Empty Feistel-round map — the default for `layoutNode`/`layoutRoot`'s
 * `feistelRounds` param so callers (and the test suite) that don't pass it
 * keep the generic group layout byte-identically. A round id present in the
 * map triggers the canonical two-column Feistel layout (see `feistel-layout.ts`).
 */
const EMPTY_FEISTEL_ROUNDS: ReadonlyMap<string, FeistelRoundShape> = new Map();

/**
 * Empty Twofish-round map — the parallel default for the `twofishRounds` param
 * (see `EMPTY_FEISTEL_ROUNDS`). A round id present here triggers the canonical
 * 4-rail Twofish layout (see `twofish-layout.ts`) instead of the generic stack.
 */
const EMPTY_TWOFISH_ROUNDS: ReadonlyMap<string, TwofishRoundShape> = new Map();

/**
 * Empty ARX double-round map — the third parallel default (see
 * `EMPTY_FEISTEL_ROUNDS`). A group id present here lays out as the canonical
 * two-tier quarter-round grid (see `arx-round-layout.ts`) instead of a 98-chip
 * vertical ribbon.
 */
const EMPTY_ARX_ROUNDS: ReadonlyMap<string, ArxDoubleRoundShape> = new Map();

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
   * consumer they touch.
   *
   * **Identity, not position (Slice S2(j2), 2026-05-26).** Prior to
   * S2(j2) this also drove the visual y-lift and source-x offset for
   * every replica. SHA-256 exposed the cost: with 4 replicated sources
   * at root (K-to-aux=0, W-publish=1, split-wv=2, split-H=3), the
   * s-stages (which see only split-wv + split-H) got rows 2 + 3 worth
   * of lift (252 + 340 px above the s_i chip) even though rows 0/1
   * sat empty there. Local densification — see `localRowOf` /
   * `localTotalOf` — now drives placement; `rowOfSource` survives as
   * the comparator key for `consumerPortOffset`'s within-bucket
   * sort and as the canonical source-identity surface that the user
   * tracks via the replica chip label (NOT by absolute y position).
   */
  readonly rowOfSource: ReadonlyMap<string, number>;
  /**
   * Slice S2(j2) (2026-05-26): replica id → local row index 0..M-1 at
   * its consumer, where M = number of distinct sources targeting this
   * consumer. Replicas at one consumer are sorted by `rowOfSource` first
   * so the within-consumer ordering matches what the global pool would
   * have produced — preserves "Round 5 and Round 19 see K-to-aux at the
   * same local row" — but unused global rows are squeezed out so the
   * s-stages no longer pay for empty rows 0+1 above them. Drives
   * `replicaSlotPosition` y-lift + `replicaSourceXOffset` x-shift.
   */
  readonly localRowOf: ReadonlyMap<string, number>;
  /**
   * Slice S2(j2) companion: replica id → M, the total replica count at
   * this replica's consumer. Used by `replicaSourceXOffset` to compute
   * the `(localRow − (M − 1)/2) * step` spread — so 2 replicas at one
   * consumer get offsets ±step/2 regardless of how many other sources
   * are globally replicated elsewhere on the canvas.
   */
  readonly localTotalOf: ReadonlyMap<string, number>;
};

const EMPTY_REPLICA_PLACEMENT: ReplicaPlacement = {
  isReplica: new Set(),
  consumerOf: new Map(),
  sourceOf: new Map(),
  rowOfSource: new Map(),
  localRowOf: new Map(),
  localTotalOf: new Map(),
};

/**
 * Per-consumer port-slot assignment for the consumer-side x-offset
 * (port-spreading-consumer-head plan, 2026-05-16). Replaces the global-
 * row formula in the old `replicaTargetXOffset` with a per-consumer slot
 * index so each consumer's incoming edges spread across its top edge
 * regardless of canvas-wide source counts.
 *
 * **Why per-consumer:** Slice 7c manual smoke surfaced two distinct
 * fan-IN ambiguity mechanisms at collapsed-iterate chip heads —
 * confirmed via `it.fails` tests in
 * `tests/graph-view-port-spreading.test.ts`:
 *
 *   1. **Collision at offset 0** — the old formula `(row - (total-1)/2)
 *      * portGap` returns 0 for any source mapped to the middle global
 *      row (whenever `total` is odd). A non-replica edge also returned
 *      0 (no row). Two distinct logical incoming edges landed at the
 *      same x on the consumer's top.
 *   2. **Skipped-global-rows inflate the spread** — a consumer with
 *      local fan-in N from M > N global sources got offsets spanning
 *      more than (N-1) * portGap because skipped rows counted toward
 *      the formula. Adjacent local edges sat 2 * portGap (or further)
 *      apart instead of exactly portGap.
 *
 * Per-consumer slot assignment fixes both. Each consumer gets its own
 * slot range 0..localCount-1, with adjacent slots exactly portGap apart.
 *
 * **Inherits row ordering from ReplicaPlacement** — the comparator sorts
 * each consumer's incoming edges by `rowOfSource.get(canonicalSource)`,
 * falling back to Infinity for non-replicas. Two consequences:
 *
 *   - Source-side staggering (still global-row-based in
 *     `replicaSourceXOffset`) stays aligned with the target-side spread:
 *     at any consumer, row N's source-x and slot's target-x sweep in
 *     the same direction. No arrow crossovers within a consumer.
 *   - Cross-canvas eye-tracking partially survives: a source's
 *     RELATIVE position among its consumer's incoming edges stays
 *     stable under canvas-wide edits that don't touch the consumer's
 *     fan-in. What's traded: the absolute x of source A varies per
 *     consumer (depends on which subset of sources lands there).
 *
 * **Kind-agnostic** — the row-ordering comparator never reads
 * `edge.kind`. Tiebreakers (`edge.from`, `auxKey`, then `kind`) are
 * deterministic but kind-agnostic in spirit. Pre-verifies Slice 7b's
 * `kind === "aux"` filter drop won't surprise port-spreading: state
 * replicas slot into the same pool as aux replicas, ordered by row.
 *
 * **Non-replica edges fall to the rightmost slots** (row = Infinity).
 * Today's only common case is the state-spine edge into a leaf where
 * everything else is an aux replica — pedagogically the state arrow
 * sits to the right of all the round-key fan-out arrows, which mirrors
 * how the user reads the cipher "state flows along, aux is dropped in
 * from above-and-left."
 */
export type ConsumerPortAssignment = {
  /**
   * edge reference → slot index (0..localCount-1) at its consumer's
   * VISUAL target. Empty entries for edges at single-incoming consumers
   * (no spread needed; `consumerPortOffset` short-circuits to 0 via the
   * `slot === undefined` branch). Keyed by edge reference, so each
   * render's edge objects map directly to their assigned slots.
   */
  readonly slotOf: ReadonlyMap<GraphEdge, number>;
  /**
   * edge reference → total number of edges in this edge's bucket. Same
   * value for every edge in the same bucket; tracking per-edge (not
   * per-target-id) keeps `consumerPortOffset` oblivious to the bucket
   * key strategy (visual target vs raw `edge.to`). Empty for
   * single-incoming consumers (consumerPortOffset's `slot === undefined`
   * short-circuit handles them).
   */
  readonly localCountOf: ReadonlyMap<GraphEdge, number>;
  /**
   * Visual target id per visible bucket (those with localCount ≥ 2),
   * exposed so tests can assert "this consumer has N incoming edges"
   * without needing to count via slotOf walks. Single-incoming
   * consumers are NOT included — they have no slot entries.
   */
  readonly bucketSizeByTarget: ReadonlyMap<string, number>;
};

const EMPTY_PORT_ASSIGNMENT: ConsumerPortAssignment = {
  slotOf: new Map(),
  localCountOf: new Map(),
  bucketSizeByTarget: new Map(),
};

/**
 * Build the per-consumer port-slot map. Walks edges once, buckets by
 * VISUAL target (see `visualTargetOf` below), sorts each multi-incoming
 * bucket by row order (inherited from `replicas.rowOfSource`), assigns
 * slots 0..N-1 within each bucket. O(E log E) overall (the per-bucket
 * sort cost dominates).
 *
 * **Why visual target, not raw `edge.to`** (2026-05-17 followup):
 * `visualEdgeTargetId` retargets replica edges whose `edge.to` is an
 * iterate container with a non-chip first body step → the arrow visually
 * lands at that first body step (slice-2 anchor). When the renderer
 * does this retargeting but `buildConsumerPortAssignment` buckets by
 * raw `edge.to`, two edges that visually converge at the same node
 * (one with `edge.to = iterate`, retargeted; one with `edge.to =
 * first-body-step`, direct) end up in DIFFERENT raw buckets, both at
 * offset 0 — visible collision. Bucketing by visual target merges them
 * into one slot pool. The optional `visualTargetOf` parameter defaults
 * to the identity (`e => e.to`) so existing tests with synthetic
 * graphs and no iterates keep their current behavior.
 *
 * **Comparator** (sorting incoming edges at one consumer):
 *
 *   1. **(Optional, when `sourceXOf` is supplied)** Visual source x of
 *      the canonical source, ascending — leftmost source on the canvas
 *      lands in the leftmost slot, so an arrow from a chip sitting at
 *      x=200 lands left of an arrow from a chip at x=350. Eliminates
 *      the visual-crossing case where two non-replica sources (both
 *      with `rowOfSource` undefined → Infinity) fall through to an
 *      alphabetical `edge.from` tiebreak that has no relation to their
 *      on-canvas position. Surfaced 2026-05-17 on AES-128 ECB: with
 *      `split-blocks` LEFT of `compute-block-count` in the spec, the
 *      latter (alphabetically 'c' < 's') won slot 0 and its arrow
 *      crossed split-blocks' arrow at the iterate's top edge. Only
 *      applies when sourceXOf returns DEFINED values for BOTH edges
 *      AND the values differ — replica edges whose canonical source
 *      was removed from the graph (Slice 7b) return undefined and
 *      fall through to the row-based ordering below, preserving the
 *      "stack closest to consumer = row 0 = leftmost slot" property
 *      for replicas.
 *   2. `rowOfSource.get(canonicalSource)` ascending — replicas before
 *      non-replicas (non-replicas get Infinity, so they sort last);
 *      among replicas, lower global row first.
 *   3. `edge.from` ascending — deterministic tiebreak when two edges
 *      share a canonical source (rare: only two replicas pointing at
 *      one consumer, which `replicateHighFanoutSources` doesn't
 *      produce today, but the comparator stays robust).
 *   4. `edge.auxKey` ascending — tiebreak for state-vs-aux from the
 *      same from→to.
 *   5. `edge.kind` ascending — final lexicographic tiebreak ("aux" <
 *      "state"). Degenerate; only matters when 1+2+3+4 all tie.
 */
const buildConsumerPortAssignment = (
  graph: CipherGraph,
  replicas: ReplicaPlacement,
  visualTargetOf?: (e: GraphEdge) => string,
  /**
   * Optional callback returning the canonical source's visual x on the
   * canvas. The renderer wires it from a baseline-layout memo
   * (`layoutRoot(graph(), pinned, consts, auxOnlyRoots)` with no
   * port-assignment input, so the call is non-recursive — slot ordering
   * depends on layout but layout's `slotXShift` only consults the
   * post-sort assignment). Returning `undefined` for a source that
   * isn't in the layout (e.g. the canonical source of a replica edge,
   * since `replicateHighFanoutSources` removes original sources from
   * the node set) makes the comparator fall through to today's
   * row-based ordering — replicas keep their row-stable slot pattern.
   *
   * Tests omit the callback to assert the pre-2026-05-17 baseline
   * ordering; the field stays optional so synthetic-graph fixtures
   * (no boxes available) still drive `buildConsumerPortAssignment`
   * end-to-end.
   */
  sourceXOf?: (canonicalSource: string) => number | undefined,
  /**
   * Optional callback returning the VISUAL ENTRY SIDE the edge will
   * actually use on the consumer's rectangle: `"top"` / `"bottom"` /
   * `"left"` / `"right"`. When provided, slot assignment buckets edges
   * by `(consumer, side)` instead of `(consumer)` alone — so a
   * consumer with one incoming state-spine on its top edge AND one
   * incoming aux from the left no longer treats them as competing for
   * a single slot pool. Pre-2026-05-19, both edges got slot offsets
   * (because the bucket was target-only), which shifted the state-
   * spine arrow's target-x off centre and made the "last arrow in
   * each column" of every AES round group render visibly crooked.
   *
   * **Side classification** (caller's responsibility — must match
   * `EdgePath`'s `geom()` regime detection):
   *   - feedback edges → "top" (the overhead arc lands on top)
   *   - horizOverlap && !vertOverlap → vertical regime →
   *     `"top"` if target sits below source else `"bottom"`
   *   - otherwise → horizontal regime →
   *     `"left"` if target sits right of source else `"right"`
   *
   * Returning `undefined` for a single edge falls back to consumer-
   * keyed bucketing for that edge (today's behaviour). Tests omit the
   * callback to assert the pre-2026-05-19 baseline; production wires
   * it from the same `boxes` map that `sourceXOf` reads.
   *
   * **`bucketSizeByTarget` stays consumer-wide.** The map remains the
   * "how many edges target this consumer, total" surface tests already
   * use. A consumer whose 2 edges split 1+1 across two sides will
   * still appear in the map with value 2 — the entry is added when at
   * least ONE side has a multi-edge bucket OR the consumer's overall
   * edge count exceeds 1, whichever is more permissive. Callers that
   * specifically want per-side counts can compute them from `slotOf`
   * + `localCountOf`.
   */
  sideOf?: (e: GraphEdge) => "top" | "bottom" | "left" | "right" | undefined,
): ConsumerPortAssignment => {
  if (graph.edges.length === 0) return EMPTY_PORT_ASSIGNMENT;
  const canonicalSource = (e: GraphEdge): string => replicas.sourceOf.get(e.from) ?? e.from;
  const rowOf = (e: GraphEdge): number => {
    const cs = canonicalSource(e);
    const row = replicas.rowOfSource.get(cs);
    return row !== undefined ? row : Number.POSITIVE_INFINITY;
  };
  const xOf = (e: GraphEdge): number | undefined => {
    if (sourceXOf === undefined) return undefined;
    return sourceXOf(canonicalSource(e));
  };
  const targetKey = visualTargetOf ?? ((e: GraphEdge) => e.to);
  // Bucket every edge under its VISUAL consumer (see doc above for why
  // not raw edge.to). When `sideOf` is provided, append the entry side
  // to the key so distinct rectangle sides get independent slot pools —
  // a vertical-regime state-spine arrow on a consumer's TOP edge no
  // longer competes for slots with a horizontal-regime aux arrow on
  // the same consumer's LEFT edge. When `sideOf` is omitted or returns
  // undefined, the key reduces to the bare consumer id — matching the
  // pre-2026-05-19 single-bucket-per-consumer behaviour that test
  // fixtures (no box layout available) rely on.
  const bucketKey = (e: GraphEdge): string => {
    if (sideOf === undefined) return targetKey(e);
    const side = sideOf(e);
    return side === undefined ? targetKey(e) : `${targetKey(e)}|${side}`;
  };
  const incomingByConsumer = new Map<string, GraphEdge[]>();
  for (const e of graph.edges) {
    const key = bucketKey(e);
    let bucket = incomingByConsumer.get(key);
    if (bucket === undefined) {
      bucket = [];
      incomingByConsumer.set(key, bucket);
    }
    bucket.push(e);
  }
  const slotOf = new Map<GraphEdge, number>();
  const localCountOf = new Map<GraphEdge, number>();
  const bucketSizeByTarget = new Map<string, number>();
  // Track consumer-wide edge counts so a side-split consumer (e.g.
  // 1 top + 1 left) still appears in `bucketSizeByTarget` with value
  // 2 even though no per-side bucket has more than one edge. This
  // preserves the test-facing API where the map answers "is this
  // consumer multi-incoming?" — independent of side bucketing.
  for (const e of graph.edges) {
    const consumer = targetKey(e);
    bucketSizeByTarget.set(consumer, (bucketSizeByTarget.get(consumer) ?? 0) + 1);
  }
  // Drop single-incoming consumers — preserve the legacy "absent from
  // the map" semantic for them.
  for (const [consumer, count] of [...bucketSizeByTarget]) {
    if (count <= 1) bucketSizeByTarget.delete(consumer);
  }
  for (const [, edges] of incomingByConsumer) {
    // Single-incoming bucket → no spread needed; leave slotOf/
    // localCountOf empty for these. `consumerPortOffset` short-circuits
    // via `slot === undefined → 0`.
    if (edges.length <= 1) continue;
    edges.sort((a, b) => {
      // Primary: visual source x (when supplied for BOTH edges). Lets the
      // leftmost source on the canvas claim the leftmost slot. Replica
      // edges whose canonical source was removed from the graph
      // (Slice 7b) return undefined here → fall through to row.
      const xa = xOf(a);
      const xb = xOf(b);
      if (xa !== undefined && xb !== undefined && xa !== xb) {
        return xa < xb ? -1 : 1;
      }
      const ra = rowOf(a);
      const rb = rowOf(b);
      if (ra !== rb) return ra < rb ? -1 : 1;
      if (a.from !== b.from) return a.from < b.from ? -1 : 1;
      if (a.auxKey !== b.auxKey) return a.auxKey < b.auxKey ? -1 : 1;
      return a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0;
    });
    for (let i = 0; i < edges.length; i++) {
      const e = edges[i];
      if (e !== undefined) {
        slotOf.set(e, i);
        localCountOf.set(e, edges.length);
      }
    }
  }
  return { slotOf, localCountOf, bucketSizeByTarget };
};

/**
 * Producer-side mirror of `ConsumerPortAssignment`. Where the consumer
 * assignment buckets edges by their TARGET and spreads N incoming arrows
 * across the consumer's attach edge, this buckets edges by their SOURCE and
 * spreads N outgoing arrows across the producer's attach edge — so a node
 * that fans out to several consumers (e.g. AES `key-expansion` with 11 round
 * keys when replication is OFF) emits each tail from a distinct point on its
 * bottom / right edge instead of stacking them all at one centre.
 *
 * Same field shapes as `ConsumerPortAssignment` (keyed by edge reference) so
 * `producerPortOffset` reuses the centred slot math via `slotCenteredOffset`.
 * `bucketSizeBySource` is the source-keyed analogue of `bucketSizeByTarget`.
 */
export type ProducerPortAssignment = {
  /** edge → slot index (0..localCount-1) at its producer's exit edge. */
  readonly slotOf: ReadonlyMap<GraphEdge, number>;
  /** edge → number of sibling edges leaving the same producer edge. */
  readonly localCountOf: ReadonlyMap<GraphEdge, number>;
  /** source id → total outgoing-edge count, for multi-out sources only. */
  readonly bucketSizeBySource: ReadonlyMap<string, number>;
};

const EMPTY_PRODUCER_PORT_ASSIGNMENT: ProducerPortAssignment = {
  slotOf: new Map(),
  localCountOf: new Map(),
  bucketSizeBySource: new Map(),
};

/**
 * Build the per-producer port-slot map — the outgoing-edge counterpart to
 * `buildConsumerPortAssignment`. Walks edges once, buckets by
 * `(source, exit-side)`, sorts each multi-outgoing bucket so the tails fan
 * out in the same direction their targets sit (no crossovers at the source),
 * and assigns slots 0..N-1. O(E log E) overall.
 *
 * **Bucket key `(source, side)`.** A node can exit edges from more than one
 * side (some targets below → bottom edge, some to the right → right edge).
 * Keying by `(source, side)` keeps each rectangle side an independent slot
 * pool — exactly mirroring the consumer builder's `(target, side)` keying.
 * `side` is the PRODUCER's exit side (computed by the caller to match
 * `EdgePath`'s regime detection): vertical regime → `"bottom"` if the target
 * sits below the source else `"top"`; horizontal regime → `"right"` if the
 * target sits to the right else `"left"`; feedback → `"top"`.
 *
 * **Bucketing by raw `edge.from`, NOT a canonical source.** Replica nodes
 * each own a single outgoing edge, so they land in size-1 buckets →
 * `producerPortOffset` returns 0 for them. That is the desired no-op:
 * fan-out replicas already disambiguate via `replicaSourceXOffset`'s
 * diagonal stagger; producer-spread must not double-shift them.
 *
 * **Comparator** (sorting one producer's outgoing edges):
 *   1. **(Optional, when `targetCoordOf` is supplied)** Cross-axis target
 *      coordinate ascending — for a vertical exit (top/bottom edge, tails
 *      spread along X) order by the target's centre X; for a horizontal exit
 *      (left/right edge, tails spread along Y) order by the target's centre
 *      Y. So the slot nearest the consumer's side claims the matching end of
 *      the producer edge → arrows leave in target order and don't cross near
 *      the source. Falls through when coordinates are undefined or equal.
 *   2. `edge.to` ascending — deterministic tiebreak.
 *   3. `edge.auxKey` ascending — tiebreak for two ports to the same target.
 *   4. `edge.kind` ascending — final lexicographic tiebreak.
 *
 * Tests may omit `targetCoordOf` / `sideOf` to drive the deterministic
 * `edge.to`-ordered baseline against synthetic graphs with no layout.
 */
const buildProducerPortAssignment = (
  graph: CipherGraph,
  /**
   * Optional cross-axis target coordinate for the ordering above. Returns
   * the value the bucket should sort on given the edge's exit side — the
   * caller picks target-centre-X for vertical exits and target-centre-Y for
   * horizontal exits. `undefined` (no layout) falls through to the tiebreaks.
   */
  targetCoordOf?: (e: GraphEdge) => number | undefined,
  /**
   * Producer exit side — mirrors the consumer builder's `sideOf` but from
   * the source's perspective. Returning `undefined` for an edge falls back
   * to source-only bucketing for it (today's no-layout test path).
   */
  sideOf?: (e: GraphEdge) => "top" | "bottom" | "left" | "right" | undefined,
): ProducerPortAssignment => {
  if (graph.edges.length === 0) return EMPTY_PRODUCER_PORT_ASSIGNMENT;
  const bucketKey = (e: GraphEdge): string => {
    if (sideOf === undefined) return e.from;
    const side = sideOf(e);
    return side === undefined ? e.from : `${e.from}|${side}`;
  };
  const coordOf = (e: GraphEdge): number | undefined =>
    targetCoordOf === undefined ? undefined : targetCoordOf(e);
  const outgoingByProducer = new Map<string, GraphEdge[]>();
  for (const e of graph.edges) {
    const key = bucketKey(e);
    let bucket = outgoingByProducer.get(key);
    if (bucket === undefined) {
      bucket = [];
      outgoingByProducer.set(key, bucket);
    }
    bucket.push(e);
  }
  const slotOf = new Map<GraphEdge, number>();
  const localCountOf = new Map<GraphEdge, number>();
  // Source-wide outgoing count (ignoring side), so a source that exits 1 edge
  // bottom + 1 edge right still reports 2 here — the source-keyed analogue of
  // the consumer builder's `bucketSizeByTarget`.
  const bucketSizeBySource = new Map<string, number>();
  for (const e of graph.edges) {
    bucketSizeBySource.set(e.from, (bucketSizeBySource.get(e.from) ?? 0) + 1);
  }
  for (const [source, count] of [...bucketSizeBySource]) {
    if (count <= 1) bucketSizeBySource.delete(source);
  }
  for (const [, edges] of outgoingByProducer) {
    // Single-outgoing bucket → nothing to spread; leave slotOf/localCountOf
    // empty so `producerPortOffset` short-circuits via `slot === undefined`.
    if (edges.length <= 1) continue;
    edges.sort((a, b) => {
      const ca = coordOf(a);
      const cb = coordOf(b);
      if (ca !== undefined && cb !== undefined && ca !== cb) {
        return ca < cb ? -1 : 1;
      }
      if (a.to !== b.to) return a.to < b.to ? -1 : 1;
      if (a.auxKey !== b.auxKey) return a.auxKey < b.auxKey ? -1 : 1;
      return a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0;
    });
    for (let i = 0; i < edges.length; i++) {
      const e = edges[i];
      if (e !== undefined) {
        slotOf.set(e, i);
        localCountOf.set(e, edges.length);
      }
    }
  }
  return { slotOf, localCountOf, bucketSizeBySource };
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
    // Inter-row pitch uses REPLICA_STACK_GAP (48) instead of FLOW_GAP
    // (24) since 2026-05-17 — the ×N bundle pills sit at arrow
    // midpoints, and a 24 px gap let adjacent pills crowd each other.
    // See `BASE_REPLICA_STACK_GAP` for the user-feedback context.
    y: baseY - row * (consts.LEAF_H + consts.REPLICA_STACK_GAP),
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
 * Single-row case (`maxRow === 0`) = `LEAF_H + REPLICA_LIFT_GAP`,
 * byte-identical to the single-replica path. Multi-row case grows with
 * `REPLICA_STACK_GAP` per extra row, matching `replicaSlotPosition`'s
 * row-spacing.
 */
// Implementation note: row 0 uses REPLICA_LIFT_GAP (36) instead of
// STACK_GAP (6) — the wider gap leaves visible arrow-shaft room
// after ARROW_INSET. Higher rows use REPLICA_STACK_GAP (48) since
// 2026-05-17 — see `BASE_REPLICA_STACK_GAP` for the rationale.
const replicaLiftHeight = (maxRow: number, consts: LayoutConstants): number => {
  if (maxRow < 0) return 0;
  return (
    consts.LEAF_H + consts.REPLICA_LIFT_GAP + maxRow * (consts.LEAF_H + consts.REPLICA_STACK_GAP)
  );
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
  //
  // Spine-replicas (2026-05-17 replica-scope-aware fix) are EXCLUDED
  // from `isReplica` so the lift-above-consumer placement loops in
  // `layoutNode` / `layoutRoot` flow them as regular leaves at the
  // source's old spec slot. They still carry `replicaOf` for click-
  // through-to-source-trace and for replica chip styling at the JSX
  // boundary — `isReplica` is the LAYOUT-MACHINERY set, narrower than
  // "all nodes with `replicaOf` set."
  //
  // Aux-fan-out replicas (every other `${src}@->${consumer}`) still
  // enter `isReplica` and get stacked above their consumer as before.
  // `rowOfSource` is keyed by SOURCE id (not replica id), so the row
  // assignment still works correctly when the spine-replica is the
  // first encountered replica of its source — the next aux-fan-out
  // replica of the same source assigns the row, and all subsequent
  // aux replicas of that source share it. The pathological case
  // "source has ONLY a spine-replica, no aux fan-out" leaves
  // `rowOfSource` without an entry — fine, because nothing queries
  // it (the spine-replica isn't in `isReplica`, so the placement loops
  // never look up its row).
  for (const n of graph.nodes) {
    if (n.replicaOf === undefined) continue;
    if (n.isSpineReplica) continue;
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

  // Slice S2(j2) — per-consumer LOCAL row densification.
  //
  // The global rowOfSource gives source A row N globally. Pre-S2(j2)
  // that row drove BOTH the y-lift above each consumer AND the
  // source-x offset for the diagonal arrow start. SHA-256 surfaced
  // the cost: with 4 replicated root sources, rows 2 and 3 lift
  // their replicas 252 / 340 px above their consumers — wasted
  // vertical space at consumers that don't have rows 0/1 nearby.
  //
  // Densification: group replicas by their consumer, sort each
  // group by the source's global row (preserves cross-consumer
  // ordering: K-to-aux at local row 0 above Round 5 AND above
  // Round 19), assign local rows 0..M-1. The source's identity is
  // still trackable by the replica's chip label; what changes is
  // the absolute y-row no longer matches across distant consumer
  // clusters.
  const replicasByConsumer = new Map<string, string[]>();
  for (const replicaId of isReplica) {
    const consumerId = consumerOf.get(replicaId);
    if (consumerId === undefined) continue;
    const arr = replicasByConsumer.get(consumerId) ?? [];
    arr.push(replicaId);
    replicasByConsumer.set(consumerId, arr);
  }
  const localRowOf = new Map<string, number>();
  const localTotalOf = new Map<string, number>();
  for (const replicaIds of replicasByConsumer.values()) {
    // Sort by source's global row so the within-cluster ordering
    // mirrors the pre-S2(j2) behavior for consumer clusters where
    // every source actually has a replica (e.g., AES rounds where
    // K-to-aux + W-publish both target every round → 2 replicas per
    // round, local rows 0 + 1, same as their global rows).
    replicaIds.sort((a, b) => {
      const sa = sourceOf.get(a);
      const sb = sourceOf.get(b);
      const ra = sa !== undefined ? (rowOfSource.get(sa) ?? 0) : 0;
      const rb = sb !== undefined ? (rowOfSource.get(sb) ?? 0) : 0;
      return ra - rb;
    });
    const total = replicaIds.length;
    for (let i = 0; i < total; i++) {
      const rid = replicaIds[i];
      if (rid === undefined) continue;
      localRowOf.set(rid, i);
      localTotalOf.set(rid, total);
    }
  }

  return { isReplica, consumerOf, sourceOf, rowOfSource, localRowOf, localTotalOf };
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
  /**
   * Per-id `(dx, dy)` deltas applied AFTER the auto-laid position is
   * computed (draggable-replicas plan, 2026-05-19). Targets synthetic ids
   * — aux replicas (`${source}@->${consumer}`) and block chips
   * (`${iterateId}@block${i}`) — whose anchor is another node and whose
   * "natural slot" is derived from that anchor's box. The leaf-and-replica
   * placement sites below add the delta to the rendered box while the
   * RETURN value of `layoutNode` (used by the parent's child-flow cursor)
   * stays at the auto position — so pinning a chip doesn't reflow its
   * siblings to fill the vacated slot.
   */
  relativePins: ReadonlyMap<string, { dx: number; dy: number }>,
  /**
   * OFFSETS-HATCH (2026-05-28 experiment, `?offsets=1`). When true, the
   * group branch staircases its children right (+LEAF_W/2 cumulative,
   * vertical-flow context) and the iterate branch alternates its
   * children up/down (+LEAF_H on odd index, horizontal-flow context).
   * Defaults to false so existing tests that drive `layoutNode` /
   * `layoutRoot` with the pre-hatch positional arity keep byte-identical
   * layout.
   */
  offsetsEnabled = false,
  /**
   * Feistel-shaped round groups (id → derived `FeistelRoundShape`). A group
   * whose id is in this map lays its children out in the canonical two-column
   * Feistel form (see `feistel-layout.ts`) instead of the generic vertical
   * stack. Defaults empty so non-Feistel specs + the test suite keep the
   * generic layout.
   */
  feistelRounds: ReadonlyMap<string, FeistelRoundShape> = EMPTY_FEISTEL_ROUNDS,
  /**
   * Twofish-shaped round groups (id → derived `TwofishRoundShape`). Parallel to
   * `feistelRounds`: a group whose id is here lays out as the canonical 4-rail
   * Twofish cell (see `twofish-layout.ts`). Kept a separate param so the 2-way
   * Feistel path is byte-identically untouched (zero regression).
   */
  twofishRounds: ReadonlyMap<string, TwofishRoundShape> = EMPTY_TWOFISH_ROUNDS,
  /**
   * ARX-shaped double-round groups (id → derived `ArxDoubleRoundShape`), from
   * ChaCha20 or Salsa20 alike. The third member of the canonical-layout family:
   * a group whose id is here lays out as the two-tier quarter-round grid (see
   * `arx-round-layout.ts`). Kept a separate param for the same reason as
   * `twofishRounds` — the Feistel and Twofish paths stay byte-identically
   * untouched.
   */
  arxRounds: ReadonlyMap<string, ArxDoubleRoundShape> = EMPTY_ARX_ROUNDS,
): Box => {
  const container = containersById.get(id);
  const pin = pinned.get(id);
  const startX = pin?.x ?? cursorX;
  const startY = pin?.y ?? cursorY;

  if (!container) {
    // Leaf: fixed-size rectangle. Apply the relative delta to the
    // rendered box only — the returned `autoBox` is used by the parent
    // for flow advancement, so the chip's pin doesn't drag its siblings.
    const autoBox: Box = { x: startX, y: startY, w: consts.LEAF_W, h: consts.LEAF_H };
    const delta = relativePins.get(id);
    if (delta) {
      out.set(id, { x: autoBox.x + delta.dx, y: autoBox.y + delta.dy, w: autoBox.w, h: autoBox.h });
    } else {
      out.set(id, autoBox);
    }
    return autoBox;
  }

  // Collapsed container: render as a leaf-sized chip; skip child recursion.
  // `collapseGraph` already cleared childIds for collapsed containers, so
  // this check is `childIds.length === 0` rather than a separate flag —
  // belt and braces, since an iterate with zero body children would also
  // hit this branch (and render correctly as an empty chip). The delta
  // application is the same shape as the leaf branch above; the only
  // dragged-chip path that flows through here is a (rare) hypothetical
  // collapsed-container relative pin — the production drag UI gates
  // relative pinning to replica + block-chip nodes by construction, not
  // collapsed groups/iterates.
  if (container.childIds.length === 0) {
    const autoBox: Box = { x: startX, y: startY, w: consts.LEAF_W, h: consts.LEAF_H };
    const delta = relativePins.get(id);
    if (delta) {
      out.set(id, { x: autoBox.x + delta.dx, y: autoBox.y + delta.dy, w: autoBox.w, h: autoBox.h });
    } else {
      out.set(id, autoBox);
    }
    return autoBox;
  }

  // Canonical Feistel-round layout: a round group whose wiring matches the
  // split→F→xor→concat shape lays its children out as the textbook two-column
  // Feistel cell (L rail left, F-function right, swap-bearing recombine at the
  // bottom) instead of the generic vertical stack. The children are all leaves
  // (split / F-stack / fxor / recombine, plus any round-key replica), so we set
  // their boxes directly — no recursion needed. `relativePins` still apply so a
  // user can drag an individual leaf. See `feistel-layout.ts`.
  const feistel = feistelRounds.get(id);
  if (container.kind === "group" && feistel !== undefined) {
    const innerX = startX + consts.CONTAINER_PAD;
    const innerY = startY + HEADER_H + consts.CONTAINER_PAD;
    const placement = feistelRoundPlacement(feistel, container.childIds, {
      leafW: consts.LEAF_W,
      leafH: consts.LEAF_H,
      isReplica: (cid) => replicas.isReplica.has(cid),
      consumerOf: (cid) => replicas.consumerOf.get(cid),
    });
    for (const childId of container.childIds) {
      const off = placement.offsets.get(childId);
      if (off === undefined) continue;
      const delta = relativePins.get(childId);
      out.set(childId, {
        x: innerX + off.dx + (delta?.dx ?? 0),
        y: innerY + off.dy + (delta?.dy ?? 0),
        w: consts.LEAF_W,
        h: consts.LEAF_H,
      });
    }
    const w = placement.bodyW + 2 * consts.CONTAINER_PAD;
    const h = HEADER_H + placement.bodyH + 2 * consts.CONTAINER_PAD;
    const box: Box = { x: startX, y: startY, w, h };
    out.set(id, box);
    return box;
  }

  // Canonical Twofish 4-rail layout — the same idea as the Feistel branch above
  // but for Twofish's wider round (two g boxes, PHT, two mix rails). See
  // `twofish-layout.ts`. Children are all leaves, so we set their boxes
  // directly; `relativePins` still apply.
  const twofish = twofishRounds.get(id);
  if (container.kind === "group" && twofish !== undefined) {
    const innerX = startX + consts.CONTAINER_PAD;
    const innerY = startY + HEADER_H + consts.CONTAINER_PAD;
    const placement = twofishRoundPlacement(twofish, container.childIds, {
      leafW: consts.LEAF_W,
      leafH: consts.LEAF_H,
      isReplica: (cid) => replicas.isReplica.has(cid),
      consumerOf: (cid) => replicas.consumerOf.get(cid),
    });
    for (const childId of container.childIds) {
      const off = placement.offsets.get(childId);
      if (off === undefined) continue;
      const delta = relativePins.get(childId);
      out.set(childId, {
        x: innerX + off.dx + (delta?.dx ?? 0),
        y: innerY + off.dy + (delta?.dy ?? 0),
        w: consts.LEAF_W,
        h: consts.LEAF_H,
      });
    }
    const w = placement.bodyW + 2 * consts.CONTAINER_PAD;
    const h = HEADER_H + placement.bodyH + 2 * consts.CONTAINER_PAD;
    const box: Box = { x: startX, y: startY, w, h };
    out.set(id, box);
    return box;
  }

  // Canonical ARX double-round layout — eight quarter-round blocks in two tiers
  // (the round that reads the split above the one that consumes its outputs:
  // ChaCha's column/diagonal, Salsa's column/row), each block the cipher's own
  // four written lines of three operations. See `arx-round-layout.ts`. Children
  // are all leaves.
  const arx = arxRounds.get(id);
  if (container.kind === "group" && arx !== undefined) {
    const innerX = startX + consts.CONTAINER_PAD;
    const innerY = startY + HEADER_H + consts.CONTAINER_PAD;
    const placement = arxDoubleRoundPlacement(arx, container.childIds, {
      leafW: consts.LEAF_W,
      leafH: consts.LEAF_H,
    });
    for (const childId of container.childIds) {
      const off = placement.offsets.get(childId);
      if (off === undefined) continue;
      const delta = relativePins.get(childId);
      out.set(childId, {
        x: innerX + off.dx + (delta?.dx ?? 0),
        y: innerY + off.dy + (delta?.dy ?? 0),
        w: consts.LEAF_W,
        h: consts.LEAF_H,
      });
    }
    const w = placement.bodyW + 2 * consts.CONTAINER_PAD;
    const h = HEADER_H + placement.bodyH + 2 * consts.CONTAINER_PAD;
    const box: Box = { x: startX, y: startY, w, h };
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
    // Slice S2(j2) — read LOCAL row (per-consumer densified) instead of
    // the source's global row. Each lifted replica's y-lift is its
    // local row * (LEAF_H + REPLICA_STACK_GAP); the maxLiftRow tells
    // `replicaLiftHeight` how many rows to budget. For groups whose
    // children consume only a SUBSET of the globally-replicated sources,
    // this collapses unused row slots — SHA-256's s-stages drop from
    // local row 2/3 (was the global row index) back to row 0/1.
    let maxLiftRow = -1;
    for (const rId of liftedReplicas) {
      const row = replicas.localRowOf.get(rId) ?? 0;
      if (row > maxLiftRow) maxLiftRow = row;
    }
    const liftH = replicaLiftHeight(maxLiftRow, consts);

    const innerX = startX + consts.CONTAINER_PAD + gutterW;
    let innerY = startY + HEADER_H + consts.CONTAINER_PAD + liftH;
    let maxChildW = 0;
    let lastChildBottom = innerY;
    // OFFSETS-HATCH: a group is a VERTICAL-flow context, so its children
    // staircase RIGHT — child i shifted +LEAF_W/2 × i from the column's
    // left edge, cumulative, on top of the normal vertical advance.
    // `maxStaircaseRight` tracks the rightmost staircased child so the
    // box width below can grow to contain the diagonal.
    const staircaseStep = offsetsEnabled ? Math.round(consts.LEAF_W / 2) : 0;
    let childIndex = 0;
    let maxStaircaseRight = innerX;
    for (const childId of normalChildren) {
      // Capture innerY BEFORE the call so cursor advancement uses the
      // NATURAL flow position, not the post-pin rendered position. Phase 6e
      // bug fix: previously `innerY = childBox.y + childBox.h + STACK_GAP`
      // used the child's RENDERED y, so pinning round.5 up shifted the
      // cursor that placed round.6, dragging round.6..16 along with it.
      // Mirrors `layoutRoot`'s root-level pattern (line 1576/1593:
      // `const naturalX = cursorX; ... cursorX = naturalX + box.w + FLOW_GAP`)
      // which already keeps root containers' siblings independent of one
      // pinned sibling. The same property should hold for nested children
      // inside a group — that's the user's "Rounds" container, where 16
      // feistel-rounds stack vertically.
      //
      // `lastChildBottom` still uses the rendered position because the
      // container's BODY height has to grow to contain the rendered
      // (pinned) children — otherwise a user-pinned chip dragged below
      // its auto position would visually escape the container's bottom
      // edge. The two computations have distinct jobs: `innerY` is the
      // next sibling's natural cursor (stable under pin); `lastChildBottom`
      // is the container's height-extent (grows under pin).
      const naturalY = innerY;
      const childX = innerX + childIndex * staircaseStep;
      const childBox = layoutNode(
        childId,
        childX,
        innerY,
        containersById,
        pinned,
        out,
        consts,
        replicas,
        relativePins,
        offsetsEnabled,
        feistelRounds,
        twofishRounds,
        arxRounds,
      );
      innerY = naturalY + childBox.h + consts.STACK_GAP;
      const renderedBottom = childBox.y + childBox.h;
      const autoBottom = naturalY + childBox.h;
      if (renderedBottom > lastChildBottom) lastChildBottom = renderedBottom;
      if (autoBottom > lastChildBottom) lastChildBottom = autoBottom;
      if (childBox.w > maxChildW) maxChildW = childBox.w;
      const childRight = childX + childBox.w;
      if (childRight > maxStaircaseRight) maxStaircaseRight = childRight;
      childIndex += 1;
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
      const delta = relativePins.get(replicaId);
      out.set(replicaId, {
        x: replicaX + (delta?.dx ?? 0),
        y: replicaY + (delta?.dy ?? 0),
        w: consts.LEAF_W,
        h: consts.LEAF_H,
      });
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
      // Slice S2(j2) — local row drives placement; see ReplicaPlacement
      // docstring for the global-vs-local split.
      const row = replicas.localRowOf.get(replicaId) ?? 0;
      const slot = replicaSlotPosition(consumerBox.x, consumerBox.y, row, consts);
      const delta = relativePins.get(replicaId);
      const finalX = slot.x + (delta?.dx ?? 0);
      const finalY = slot.y + (delta?.dy ?? 0);
      out.set(replicaId, {
        x: finalX,
        y: finalY,
        w: consts.LEAF_W,
        h: consts.LEAF_H,
      });
      // Use the post-delta x for extent tracking — a chip dragged right
      // grows the column to fit; dragging left can't shrink it (the column
      // already accommodated the auto position, smaller numbers are fine).
      const replicaRight = finalX + consts.LEAF_W;
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
    // OFFSETS-HATCH: the staircase pushes the last child right by
    // `(N-1) × LEAF_W/2`; `maxStaircaseRight - innerXForCol` is that
    // child's right edge measured from the column's left edge, so the
    // column must be at least that wide to contain the diagonal.
    const staircaseColumnW = offsetsEnabled ? maxStaircaseRight - innerXForCol : 0;
    const columnW = Math.max(maxChildW, consts.LEAF_W, liftReplicaColumnW, staircaseColumnW);
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
    // Slice S2(j2) — use local row.
    const row = replicas.localRowOf.get(childId) ?? 0;
    if (row > iterateMaxRow) iterateMaxRow = row;
  }
  const replicaLiftH = hasIterateReplicas ? replicaLiftHeight(iterateMaxRow, consts) : 0;

  let innerX = startX + consts.CONTAINER_PAD;
  const innerY = startY + HEADER_H + consts.CONTAINER_PAD + replicaLiftH;
  // Track the LOWEST child extent (max of `childBox.y + childBox.h`), NOT just
  // the tallest child height. The group branch already sizes off child-bottom;
  // the iterate branch used to size off `maxChildH` alone, so a child pinned or
  // dragged BELOW the natural row spilled out the bottom of the box (its box
  // clipped it) — exactly the hazard when hand-authoring a curated default
  // inside an expanded iterate like SHA-256's per-block compression fold.
  // Child-bottom tracking makes the box grow to contain dragged-down children,
  // and (as a bonus) absorbs the offsets-hatch's lowered odd rows without a
  // separate `altRowExtra` budget. Floor at `innerY` so an empty body keeps
  // the header + pad height it had before.
  let bodyBottom = innerY;
  let lastChildRight = innerX;
  // OFFSETS-HATCH: an iterate body is a HORIZONTAL-flow context, so its
  // children alternate up/down — even index at `innerY`, odd index one LEAF_H
  // lower. The lowered rows' extra extent is captured by `bodyBottom` below.
  let iterateChildIndex = 0;
  for (const childId of container.childIds) {
    if (replicas.isReplica.has(childId)) continue;
    const childAltY = offsetsEnabled && iterateChildIndex % 2 === 1 ? consts.LEAF_H : 0;
    const childBox = layoutNode(
      childId,
      innerX,
      innerY + childAltY,
      containersById,
      pinned,
      out,
      consts,
      replicas,
      relativePins,
      offsetsEnabled,
      feistelRounds,
      twofishRounds,
      arxRounds,
    );
    innerX = childBox.x + childBox.w + consts.FLOW_GAP;
    lastChildRight = childBox.x + childBox.w;
    if (childBox.y + childBox.h > bodyBottom) bodyBottom = childBox.y + childBox.h;
    iterateChildIndex += 1;
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
    // Slice S2(j2) — use local row.
    const row = replicas.localRowOf.get(childId) ?? 0;
    const slot = replicaSlotPosition(consumerBox.x, consumerBox.y, row, consts);
    const delta = relativePins.get(childId);
    const finalX = slot.x + (delta?.dx ?? 0);
    const finalY = slot.y + (delta?.dy ?? 0);
    out.set(childId, {
      x: finalX,
      y: finalY,
      w: consts.LEAF_W,
      h: consts.LEAF_H,
    });
    const replicaRight = finalX + consts.LEAF_W;
    if (replicaRight > maxIterateReplicaRight) maxIterateReplicaRight = replicaRight;
    // Replicas normally sit ABOVE the body (lifted), but a user can drag one
    // down via `relativePins`; contain it like any other child-bottom.
    if (finalY + consts.LEAF_H > bodyBottom) bodyBottom = finalY + consts.LEAF_H;
  }

  // Grow the iterate container to fit upper-row replicas that shifted
  // right past `lastChildRight`. A row-N replica above the last body
  // child extends to `lastChildBox.x + N * REPLICA_ROW_X_STEP + LEAF_W`;
  // the iterate's box must contain it.
  const effectiveLastRight = Math.max(lastChildRight, maxIterateReplicaRight);
  const w = effectiveLastRight - startX + consts.CONTAINER_PAD;
  // Height from the lowest child extent (child-bottom tracking) plus a bottom
  // pad — mirrors the group branch, and contains any dragged-down child.
  let h = bodyBottom - startY + consts.CONTAINER_PAD;
  // Extra authoring headroom for LARGE-bodied expanded iterates (today only
  // SHA-256's per-block compression fold; see `ITERATE_HEADROOM_MIN_CHILDREN`).
  // Reserve a SECOND copy of the inner-region height as empty space below the
  // body, so the window opens ~2× taller and there is room to drag the many
  // leaves into a hand-arranged default. Children are NOT moved — the space is
  // purely additive at the bottom; child-bottom tracking above then keeps any
  // leaf dragged into that space contained (so the arrangement round-trips
  // through Save/reload un-clipped). `innerRegionTop` is where lifted replicas
  // begin (the top of the inner content), so `bodyBottom - innerRegionTop` is
  // the full inner content height (replica lift + body row).
  if (container.childIds.length >= ITERATE_HEADROOM_MIN_CHILDREN) {
    const innerRegionTop = startY + HEADER_H + consts.CONTAINER_PAD;
    h += Math.max(0, bodyBottom - innerRegionTop);
  }
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
  /**
   * Per-consumer port assignment (post-bundling). When provided, root-level
   * replica chips that are the SOLE replica feeding their consumer get
   * their x shifted by `consumerPortOffset(...)` so the arrow renders
   * vertical instead of diagonal — fix for the user-flagged "arrow in
   * single replicate is still not near vertical" (2026-05-17 polish
   * smoke). Multi-replica consumers keep the column-stacked layout
   * (the user said "if we have 2 or 3 replicates it looks good").
   *
   * Optional; tests and pre-bundle callers can omit it (no shift applied —
   * byte-identical to the old layout). Production renderer wires this
   * from the `portAssignment` memo so the shift is always available.
   */
  portAssignment?: ConsumerPortAssignment,
  /**
   * Per-id `(dx, dy)` deltas for synthetic-id chips (aux replicas + block
   * chips). Applied AFTER the auto position is computed; see the parameter
   * doc on `layoutNode` for the leaf-vs-flow split. Optional and defaults
   * to empty so the existing test suite — which passes only the first
   * three positional args — continues to drive `layoutRoot` byte-
   * identically.
   *
   * Added 2026-05-19 (draggable-replicas plan, Slice 2).
   */
  relativePins: ReadonlyMap<string, { dx: number; dy: number }> = new Map(),
  /**
   * Feistel-shaped round groups (id → derived shape). Threaded down to
   * `layoutNode` so a round whose wiring matches the split→F→xor→concat shape
   * lays out as the canonical two-column Feistel cell. Optional; defaults
   * empty so the test suite + non-Feistel specs keep the generic layout.
   */
  feistelRounds: ReadonlyMap<string, FeistelRoundShape> = EMPTY_FEISTEL_ROUNDS,
  /**
   * Twofish-shaped round groups (id → derived shape). Threaded down to
   * `layoutNode` alongside `feistelRounds` so a Twofish round lays out as the
   * canonical 4-rail cell. Optional; defaults empty (generic layout).
   */
  twofishRounds: ReadonlyMap<string, TwofishRoundShape> = EMPTY_TWOFISH_ROUNDS,
  /**
   * ARX-shaped double-round groups (id → derived shape). Threaded down to
   * `layoutNode` alongside the other two so an ARX double round lays out as
   * the canonical two-tier quarter-round grid. Optional; defaults empty.
   */
  arxRounds: ReadonlyMap<string, ArxDoubleRoundShape> = EMPTY_ARX_ROUNDS,
): { boxes: Map<string, Box>; canvasW: number; canvasH: number } => {
  const containersById = new Map<string, ContainerNode>();
  for (const c of graph.containers) containersById.set(c.id, c);
  // nodesById exists so the iterate-target replica-anchor logic below can
  // discriminate "first child is a real body step" (anchor above it) from
  // "first child is a block chip" (anchor at iterate center). Post-Option-C
  // a collapsed iterate's childIds are chip ids, not body steps — the
  // anchor needs to read as "feeds the iterate as a whole," not "feeds
  // block 1 specifically." See the anchor branch in `layoutRoot`'s second
  // pass for the override.
  const nodesById = new Map<string, GraphNode>();
  for (const n of graph.nodes) nodesById.set(n.stepId, n);

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
    // Slice S2(j2) — local row gives the actual row this replica
    // occupies above its consumer. For SHA-256 root replicas at the
    // s-stages this drops from 2/3 (global) back to 0/1 (local) since
    // the s-stages don't have rows 0/1 sources targeting them.
    const row = replicas.localRowOf.get(id) ?? 0;
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

  // ── OFFSETS-HATCH (2026-05-28 experiment) ───────────────────────────
  //
  // Reads `?offsets=1` from `window.location.search`. The rule a member
  // gets depends on the FLOW ORIENTATION of the context it sits in:
  //
  //   - HORIZONTAL-flow context (root flow here; iterate body in
  //     `layoutNode`): members alternate y up/down — even index at the
  //     base row, odd index one LEAF_H lower. Collapsed round chips at
  //     root therefore zig-zag rather than staircase.
  //   - VERTICAL-flow context (expanded group body in `layoutNode`):
  //     members staircase right — each child shifted +LEAF_W/2 from the
  //     previous, cumulative, on top of the existing vertical advance.
  //
  // Root is a horizontal-flow context, so the rule HERE is alternation.
  // The staircase + iterate-cascade live in `layoutNode`'s group +
  // iterate branches (threaded via the `offsetsEnabled` param below).
  //
  // OFF (default): `altCounter` stays unread and `startY` keeps the
  // original `auxOnlyRootIds ? CANVAS_MARGIN : rowStartY` value — layout
  // byte-identical to before the hatch.
  const offsetsEnabled = isOffsetsEnabledForLayout();
  let altCounter = 0;

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
    // spine row keeps that pin. Aux-only roots are excluded from the
    // alternation (they're supporting computation on a dedicated lifted
    // row, not spine members) and don't advance the counter.
    const isAuxOnly = auxOnlyRootIds.has(id);
    const baseY = isAuxOnly ? CANVAS_MARGIN : rowStartY;
    const altOffset = offsetsEnabled && !isAuxOnly && altCounter % 2 === 1 ? consts.LEAF_H : 0;
    const startY = baseY + altOffset;
    const box = layoutNode(
      id,
      cursorX,
      startY,
      containersById,
      pinned,
      boxes,
      consts,
      replicas,
      relativePins,
      offsetsEnabled,
      feistelRounds,
      twofishRounds,
      arxRounds,
    );
    cursorX = naturalX + box.w + consts.FLOW_GAP;
    if (offsetsEnabled && !isAuxOnly) altCounter += 1;
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
  //
  // Pre-pass: count chips per consumer so the placement loop can detect
  // the single-replica case and apply the slot-offset shift (see the
  // `slotXShift` comment inside the loop). Multi-replica consumers skip
  // the shift to preserve the column-stacked visual the user finds
  // acceptable.
  const chipCountByConsumer = new Map<string, number>();
  for (const id of graph.rootIds) {
    if (!replicas.isReplica.has(id)) continue;
    const cid = replicas.consumerOf.get(id);
    if (cid === undefined) continue;
    chipCountByConsumer.set(cid, (chipCountByConsumer.get(cid) ?? 0) + 1);
  }
  for (const id of graph.rootIds) {
    if (!replicas.isReplica.has(id)) continue;
    const consumerId = replicas.consumerOf.get(id);
    if (consumerId === undefined) continue;
    const consumerBox = boxes.get(consumerId);
    if (!consumerBox) continue;
    // Slice S2(j2) — local row drives placement (see ReplicaPlacement
    // docstring). For SHA-256's s-stages this collapses split-wv from
    // y-lift = consumerY−252 to y-lift = consumerY−76, and split-H from
    // consumerY−340 to consumerY−164.
    const row = replicas.localRowOf.get(id) ?? 0;
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
    // Post-Option-C, a collapsed iterate's first non-replica child is a
    // block chip (`stepType === "__block_chip__"`), NOT a real body step.
    // Reading the chip's x as the replica anchor places the arrow tip
    // above block 1 — visually misleading because aux is consumed at
    // iteration entry and feeds ALL blocks. Override to iterate-center
    // (column-centered so multiple row-stacked replicas converge on the
    // iterate's horizontal midline) so the arrow reads as "feeds the
    // iterate," not "feeds block 1." Expanded iterates keep the
    // first-body-step anchor unchanged.
    const firstChildNode =
      firstNonReplicaChildId !== undefined ? nodesById.get(firstNonReplicaChildId) : undefined;
    const firstChildIsBlockChip = firstChildNode?.blockChipOf !== undefined;
    const iterateCenterX =
      consumerContainer?.kind === "iterate" && firstChildIsBlockChip
        ? consumerBox.x + (consumerBox.w - consts.LEAF_W) / 2
        : undefined;
    const anchorX = iterateCenterX ?? firstChildBox?.x ?? consumerBox.x;
    // Single-replica vertical-arrow shift (2026-05-17): when this
    // consumer has exactly one incoming replica chip, the consumer-port-
    // spread still gives that chip's bundle a non-center slot because
    // OTHER non-replica bundles also feed the consumer (state-spine
    // edges, plain aux edges from non-replicated sources). The chip
    // would sit at `anchorX` while its arrow target was at `anchorX +
    // slotOffset` → diagonal. Shifting the chip's x by the slot
    // offset makes the arrow vertical. Multi-replica consumers (≥2
    // chips) skip the shift — the user finds the column-stacked
    // diagonal-arrow pattern visually fine for 2-3 chips, and shifting
    // each would convert the vertical stack into a horizontal row,
    // breaking the established "stack above the consumer" visual.
    //
    // Slot lookup uses the bundle's representative edge — by bundleEdges'
    // first-encounter rule, this is the first edge in graph.edges whose
    // (from, to) matches the chip → consumer pair. Any other edge from
    // the chip is a same-bundle sibling and wouldn't be in
    // `portAssignment.slotOf`, so `consumerPortOffset` would return 0
    // for it. Defensive `find` instead of indexing for robustness against
    // a malformed graph.
    let slotXShift = 0;
    if (portAssignment !== undefined && chipCountByConsumer.get(consumerId) === 1) {
      const repEdge = graph.edges.find((e) => e.from === id && e.to === consumerId);
      if (repEdge !== undefined) {
        const portGap = Math.max(6, Math.round(consts.LEAF_W / 10));
        slotXShift = consumerPortOffset(repEdge, portAssignment, portGap);
      }
    }
    // Port-spreading polish: x/y come from `replicaSlotPosition`, which
    // applies the row-shift and REPLICA_STACK_GAP row-spacing uniformly
    // across the three placement sites. `slotXShift` is added on top
    // (single-replica vertical shift; zero for multi-replica + tests).
    const slot = replicaSlotPosition(anchorX + slotXShift, consumerBox.y, row, consts);
    const delta = relativePins.get(id);
    const finalX = slot.x + (delta?.dx ?? 0);
    const finalY = slot.y + (delta?.dy ?? 0);
    boxes.set(id, {
      x: finalX,
      y: finalY,
      w: consts.LEAF_W,
      h: consts.LEAF_H,
    });
    // Replica boxes can now extend right past the consumer's x-range
    // (row k shifts by k × REPLICA_ROW_X_STEP); track that against
    // canvas extent so the SVG width grows to fit. Post-delta x so a
    // user-dragged chip still grows the canvas to fit.
    const replicaRight = finalX + consts.LEAF_W;
    if (replicaRight > maxRight) maxRight = replicaRight;
    // Same for the bottom extent — `maxBottom` was previously only updated
    // for non-replica root entities; pre-2026-05-19 every replica sat at
    // or above CANVAS_MARGIN by construction, but a relative pin can now
    // push a chip below the spine row.
    const replicaBottom = finalY + consts.LEAF_H;
    if (replicaBottom > maxBottom) maxBottom = replicaBottom;
  }

  // Final extent pass: scan every box (including iterate-body chips and
  // group-lifted replicas at any nesting depth) for the actual right/bottom.
  // The two pre-passes above tracked `maxRight`/`maxBottom` from a curated
  // subset (root containers + root replicas) — sufficient when every
  // descendant's box stays inside its parent's natural h, but a relative-
  // pin delta on an iterate-body chip or a group-lifted replica can push
  // its box outside the parent's `box.h` (the parent's height is computed
  // from natural child sizes; the pin is applied AFTER and doesn't grow
  // the parent). Without this pass, the SVG height stayed at the natural
  // value and the user-dragged chip rendered below `canvasH` — visually
  // clipped (see draggable-replicas-layout.test.ts "canvasH grows to fit
  // a block chip dragged downward"). Cost: one O(boxes) pass; trivial
  // compared to the layout work above.
  for (const box of boxes.values()) {
    const right = box.x + box.w;
    const bottom = box.y + box.h;
    if (right > maxRight) maxRight = right;
    if (bottom > maxBottom) maxBottom = bottom;
  }

  return {
    boxes,
    canvasW: maxRight + CANVAS_MARGIN + CANVAS_TRAILING_PAD_RIGHT,
    canvasH: maxBottom + CANVAS_MARGIN + CANVAS_TRAILING_PAD_BOTTOM,
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
  // Option C: a collapsed iterate's first non-replica child is a block
  // chip (`blockChipOf !== undefined`), not a real body step. Retargeting
  // the arrow there would make it visually land on block 1 — wrong
  // pedagogically, because the aux is consumed at iteration entry and
  // feeds all blocks. When the first child is a chip, leave the arrow's
  // target at the iterate as a whole (its top edge). Mirrors the
  // anchor-x override in `layoutRoot`'s replica placement loop.
  if (firstNonReplicaChildId !== undefined) {
    const firstChildNode = nodesById.get(firstNonReplicaChildId);
    if (firstChildNode?.blockChipOf !== undefined) return edge.to;
  }
  return firstNonReplicaChildId ?? edge.to;
};

/**
 * Returns the per-consumer x-offset for one edge at its consumer's top
 * edge (port-spreading-consumer-head plan, 2026-05-16). Centered around
 * the consumer's top-edge midpoint via
 * `(slot - (localCount - 1) / 2) * portGap`.
 *
 * **Returns 0 when**:
 *   - The edge isn't in `slotOf` (single-incoming consumer — `buildConsumer
 *     PortAssignment` leaves `slotOf` empty for these consumers).
 *   - `localCount` is missing or `<= 1` (degenerate / sanity guard).
 *
 * @param edge — the edge being rendered (same `GraphEdge` reference that
 *   was passed to `buildConsumerPortAssignment`).
 * @param ports — the per-consumer port assignment from
 *   `buildConsumerPortAssignment(graph, replicaPlacement)`.
 * @param portGap — density-scaled gap between adjacent slots. The render
 *   site computes `Math.max(6, round(LEAF_W / 10))` so the spread tracks
 *   the consumer width.
 * @param cap — optional half-extent (the maximum absolute offset value the
 *   consumer can accept on its attach edge). When supplied AND the natural
 *   slot extent `((total - 1) / 2) * portGap` exceeds `cap`, the gap is
 *   scaled down to `(cap * 2) / (total - 1)` so every slot lands within
 *   `[-cap, +cap]` while remaining monotonic and evenly spaced. Mirrors
 *   the EdgePath clamps (`to.w/2 - 4` for vertical regime, `to.h/2 - 4`
 *   for horizontal regime) and prevents the slot-collision bug Slice S2(j)
 *   addressed: SHA-256 `final.assemble` has 8 incoming horizontal-regime
 *   port-flow edges; pre-S2(j) the clamp at LEAF_H/2 − 4 = ±16 collapsed
 *   raw offsets −35/−25 → −16 and +25/+35 → +16, putting two pairs of
 *   arrows at the same y. With the cap argument, gap scales to 32/7 ≈ 4.6
 *   so all 8 slots stay distinct. Omitting `cap` preserves the pre-S2(j)
 *   behavior (legacy callers in tests + the replica-chip placement site).
 *
 * Pure: reads only the precomputed assignment. The render site builds the
 * assignment once per `graph()` change in a memo (same pattern as
 * `replicaPlacement`).
 *
 * **Replaces the prior `replicaTargetXOffset` (deleted 2026-05-16).**
 * The old function distributed by global row index — confirmed buggy at
 * collapsed-iterate chip heads via the two `it.fails` tests now flipped
 * to plain `it` in `tests/graph-view-port-spreading.test.ts`. See the
 * `ConsumerPortAssignment` doc-block above for the mechanism details.
 */
/**
 * Centered, cap-aware slot offset shared by `consumerPortOffset` (incoming
 * arrows at a consumer's edge) and `producerPortOffset` (outgoing arrows at
 * a producer's edge). Given a 0-based `slot` among `total` siblings, returns
 * `(slot - (total - 1) / 2) * effectiveGap` so the slots fan out symmetrically
 * around the edge midpoint.
 *
 * **Density-aware scaling** (Slice S2(j) of the SHA-256 density-polish plan).
 * When the natural extent `((total - 1) / 2) * portGap` exceeds `cap`, shrink
 * the gap so the outermost slots land exactly on ±cap and inner slots stay
 * monotonic + evenly spaced. Without this the EdgePath clamp would collapse
 * multiple raw offsets to the same cap value, producing visually identical
 * attach points for distinct edges (the SHA-256 `s_i → final.assemble`
 * pile-up). Omitting `cap` preserves the pre-S2(j) behavior.
 */
const slotCenteredOffset = (slot: number, total: number, portGap: number, cap?: number): number => {
  if (total <= 1) return 0;
  let effectiveGap = portGap;
  if (cap !== undefined && cap > 0) {
    const maxExtent = ((total - 1) / 2) * portGap;
    if (maxExtent > cap) effectiveGap = (cap * 2) / (total - 1);
  }
  return (slot - (total - 1) / 2) * effectiveGap;
};

export const consumerPortOffset = (
  edge: GraphEdge,
  ports: ConsumerPortAssignment,
  portGap: number,
  cap?: number,
): number => {
  const slot = ports.slotOf.get(edge);
  if (slot === undefined) return 0;
  const total = ports.localCountOf.get(edge);
  if (total === undefined || total <= 1) return 0;
  return slotCenteredOffset(slot, total, portGap, cap);
};

/**
 * Outgoing-edge counterpart to `consumerPortOffset`. Returns the per-producer
 * offset for one edge at its source's exit edge, centred via the shared
 * `slotCenteredOffset`. Applied to the source-x in the vertical regime (tails
 * along the bottom/top edge) and to the source-y in the horizontal regime
 * (tails along the right/left edge) — see the `sourceXOffset` / `sourceYOffset`
 * memos in `renderBundle`.
 *
 * **Returns 0 when** the edge isn't in `slotOf` (single-outgoing producer —
 * `buildProducerPortAssignment` leaves the map empty for those) or `localCount`
 * is missing / `<= 1`. So fan-out replicas (one outgoing edge each) and any
 * source with a lone consumer render byte-identically to pre-producer-spread.
 *
 * @param edge — the rendered edge (same `GraphEdge` reference that was passed
 *   to `buildProducerPortAssignment`).
 * @param ports — the assignment from `buildProducerPortAssignment`.
 * @param portGap — density-scaled gap between adjacent slots.
 * @param cap — optional half-extent (the source's inner half-width for the
 *   vertical regime, half-height for the horizontal regime). See
 *   `slotCenteredOffset` for the scale-down behavior.
 */
export const producerPortOffset = (
  edge: GraphEdge,
  ports: ProducerPortAssignment,
  portGap: number,
  cap?: number,
): number => {
  const slot = ports.slotOf.get(edge);
  if (slot === undefined) return 0;
  const total = ports.localCountOf.get(edge);
  if (total === undefined || total <= 1) return 0;
  return slotCenteredOffset(slot, total, portGap, cap);
};

/**
 * The point on the CONSUMER box's edge where an incoming edge visually lands —
 * the box-edge anchor for the arrowhead, used to place the input-port wiring
 * dots so they sit where the arrow actually arrives (2026-07-12) rather than
 * always on the left edge. Before the canonical Feistel/Twofish cells, flow was
 * left-to-right so left-edge dots matched; those cells route flow top-to-bottom,
 * so a fixed left-edge dot no longer aligns with the incoming arrow.
 *
 * **This MUST match `EdgePath`'s `geom()` target-attach math** (search "Three
 * regimes" / the vertical/horizontal branches). It returns the point ON the box
 * edge (EdgePath then pulls the arrowhead `inset` px inside; the visible tip
 * still kisses this edge). The three regimes:
 *   - feedback → target's TOP-edge centre;
 *   - vertical (boxes share x-range, no y-overlap) → TOP edge if the source is
 *     above (`downward`), else BOTTOM, shifted by the port-spread `targetXOffset`;
 *   - horizontal (default) → LEFT edge if the source is to the left
 *     (`rightward`), else RIGHT, shifted by `targetYOffset`.
 * The offsets are clamped to the same half-extent EdgePath uses so the dot stays
 * inside the box on degenerate inputs.
 */
export const portArrivalPoint = (
  from: Box,
  to: Box,
  opts: { isFeedback: boolean; targetXOffset: number; targetYOffset: number },
): { x: number; y: number } => {
  const toCx = to.x + to.w / 2;
  const toCy = to.y + to.h / 2;
  if (opts.isFeedback) return { x: toCx, y: to.y };
  const horizOverlap = Math.min(from.x + from.w, to.x + to.w) > Math.max(from.x, to.x);
  const vertOverlap = Math.min(from.y + from.h, to.y + to.h) > Math.max(from.y, to.y);
  if (horizOverlap && !vertOverlap) {
    const downward = to.y + to.h / 2 >= from.y + from.h / 2;
    const cap = to.w / 2 - 4;
    const off = Math.max(-cap, Math.min(cap, opts.targetXOffset));
    return { x: toCx + off, y: downward ? to.y : to.y + to.h };
  }
  const rightward = to.x + to.w / 2 >= from.x + from.w / 2;
  const cap = to.h / 2 - 4;
  const off = Math.max(-cap, Math.min(cap, opts.targetYOffset));
  return { x: rightward ? to.x : to.x + to.w, y: toCy + off };
};

/**
 * The CSS colour an incoming arrow is drawn in — used to paint each input-port
 * arrival dot the SAME hue as its arrow so the eye can trace "this arrow ends
 * here" at a glance (2026-07-12, user request "make the dots the same colour as
 * the arrow"). MUST mirror `renderBundle`'s `sourceColor` resolution + the
 * `.graph-edge-*` kind defaults in `app.css`, so a dot and its arrowhead never
 * disagree:
 *   1. source-colour coding ON and this edge's canonical source has an assigned
 *      hue → that hex (endpoint-pill sources are excluded, exactly as the arrow
 *      is — they fall through to the kind default);
 *   2. otherwise the kind baseline — aux edges are `var(--accent)`
 *      (`.graph-edge` / `.graph-edge-aux`), state/spine edges `var(--text)`
 *      (`.graph-edge-state`).
 *
 * Returned as a CSS `color` value (hex or `var(--…)`); the caller sets it as the
 * handle `<g>`'s inline `color` and the dot's CSS resolves `fill: currentColor`
 * — the same carrier `EdgePath` uses, so the `:hover` / armed `fill: var(--accent)`
 * stylesheet rules still win by specificity (an inline `fill` would clobber them).
 */
export const arrivalColorFor = (
  edge: Pick<GraphEdge, "from" | "kind">,
  sourceColors: ReadonlyMap<string, string>,
  nodesById: ReadonlyMap<string, GraphNode>,
): string => {
  if (sourceColors.size > 0 && !isEndpointId(edge.from)) {
    const node = nodesById.get(edge.from);
    const canonical = node?.replicaOf ?? edge.from;
    const c = sourceColors.get(canonical);
    if (c !== undefined) return c;
  }
  return edge.kind === "aux" ? "var(--accent)" : "var(--text)";
};

/**
 * Horizontal shift applied to the SOURCE x of a replica edge's path in
 * the vertical regime. Returns a signed pixel offset; `EdgePath` adds
 * it to the source attach x (`sx`), so the arrow emerges from a
 * non-centred point on the replica's bottom edge.
 *
 * **Geometry** (2026-05-16 straight-line + offset-start-point approach):
 * uses the monotonic spread formula `(row - (total-1)/2) * step` over
 * the **per-consumer LOCAL row index** (Slice S2(j2), 2026-05-26). The
 * target-side `consumerPortOffset` uses per-consumer slot indices, and
 * those slots are assigned in `rowOfSource` (global) order — but since
 * within a single consumer's bucket the relative ordering of local and
 * global rows is identical (we sort by global then renumber locally),
 * source-x and target-x still sweep in the same direction at any given
 * consumer. Result: every arrow is a roughly parallel down-and-slightly-
 * inward line, no crossovers within a consumer.
 *
 * **What S2(j2) changed (2026-05-26).** Pre-S2(j2) the formula read from
 * `replicas.rowOfSource.get(sourceId)` (the global row) and
 * `replicas.rowOfSource.size` (the global total). SHA-256 has 4 root
 * replicated sources globally; the s-stages see only 2 of them
 * (split-wv / split-H, at global rows 2 / 3). The old formula put their
 * arrow start at `(2 − 1.5) * 32 = +16` and `(3 − 1.5) * 32 = +48` —
 * visibly off-center (the +48 nearly clips the chip's right edge). The
 * new formula uses local row 0 / 1 with total = 2 → offsets `±16`,
 * arrows visibly start near the chip's vertical centerline. AES rounds
 * see all globally-replicated sources locally (K-to-aux + W-publish,
 * local total = 2), so AES is byte-identical.
 *
 * **Why monotonic, not alternating:** an earlier draft alternated
 * `+1, −1, +2, −2, …` so each row claimed a different side of the
 * column. Visually clean for distinguishing rows in isolation, BUT
 * since the target-side spread is monotonic, the two spreads would
 * sweep different directions per row — row 0 source-centre +
 * target-left = down-left; row 1 source-right + target-centre =
 * down-left; row 2 source-left + target-right = down-right → row 0's
 * arrow crosses row 2's. User observed this directly on the canonical
 * AES-128 ECB + 3-source case: "the arrow from key-expansion does an
 * unnecessary crossover the other arrows coming from above."
 *
 * **Single-source case** (localTotal ≤ 1): returns 0. Today's AES /
 * Speck / Serpent key-expansion fan-outs all hit this branch — byte-
 * identical to pre-offset rendering, so the simple case stays clean.
 *
 * **Magnitude rationale:** LEAF_W = 132 ⇒ half-width = 66. `step = 32`
 * means a 3-source spread covers [-32, 0, +32] (total 64 px) — clearly
 * distinguishable dots without crowding the box edges. A 5-source
 * spread would reach ±64, just inside the half-width; EdgePath clamps
 * to LEAF_W/2 − 4 = 62 as a guard for any worse pathological case.
 *
 * Param shape is structural (not `ReplicaPlacement`) so tests can pass
 * a hand-rolled `{ localRowOf, localTotalOf }` literal — the helper
 * only needs those two maps. (Pre-S2(j2): `{ sourceOf, rowOfSource }`
 * — see Slice S2(j2) of the SHA-256 density-polish plan for the param
 * migration.)
 */
export const replicaSourceXOffset = (
  edge: GraphEdge,
  replicas: {
    readonly localRowOf: ReadonlyMap<string, number>;
    readonly localTotalOf: ReadonlyMap<string, number>;
  },
  step: number,
): number => {
  const row = replicas.localRowOf.get(edge.from);
  if (row === undefined) return 0;
  const total = replicas.localTotalOf.get(edge.from);
  if (total === undefined || total <= 1) return 0;
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
 * Re-exported for tests that want to drive replica placement and the
 * per-consumer port-spreading directly. `consumerPortOffset` reads only
 * the `ConsumerPortAssignment` that `buildConsumerPortAssignment` builds
 * from a `CipherGraph` + `ReplicaPlacement` pair, so tests can either
 * call both builders or hand-roll structurally-compatible literals.
 */
export { buildConsumerPortAssignment, buildProducerPortAssignment, buildReplicaPlacement };

// ─── Component ─────────────────────────────────────────────────────────────

export const GraphView = () => {
  const spec = useSpec();
  const version = useTraceVersion();
  const layoutMap = useLayoutMap();
  const density = useViewDensity();
  const rawReplicate = useReplicationEnabled();
  const replicationUserToggled = useReplicationUserToggledThisSession();
  /**
   * Effective replication switch. Returns `true` if EITHER the user
   * explicitly toggled it on this session, OR they haven't touched it yet
   * (the default is ON for every spec).
   *
   * Why default-on: port-native ciphers decompose into many fine-grained
   * leaves with high-fanout sources (e.g. SHA-256's `K-to-aux` fans out to
   * 64 rounds, `W-publish` to 64). With replication OFF the canvas is a
   * dense thicket of crossing long arrows that obscures the data flow;
   * ON splits each source into per-consumer chips that read as a sequence.
   * (Pre-Phase-C this read `if (requiresPortedDispatch(spec, registry)) return
   * true`. Since Slice 5.2 every shipped spec has been port-native, so that
   * predicate already returned true for all of them — replacing it with a
   * literal `true` is a pure simplification, behavior-identical for every
   * shipped spec, not a default change.)
   *
   * Why "user hasn't touched it" gates the auto-on: if a user toggled
   * off mid-session (across any spec), they made an explicit choice;
   * honour it everywhere until they reload the page. The session-only
   * tracker `replicationUserToggledThisSession` flips to true the
   * moment `setReplicationEnabled` is called from the toolbar checkbox.
   */
  const replicate = createMemo<boolean>(() => {
    if (replicationUserToggled()) return rawReplicate();
    return true;
  });
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

  // ─── Port-wiring (4d-bis, Slice E — click-to-arm) ──────────────────────
  // Two-click gesture: click a leaf's input-port handle to ARM, then click a
  // legal upstream source's bind handle to WIRE. The armed port lives in the
  // transient `wiring` store; here we derive the scope-legal sources for it.
  const armed = useArmedPort();
  /** Scope-legal sources for the armed input port (null when nothing armed). */
  const armedLegalSources = createMemo<LegalSource[] | null>(() => {
    const a = armed();
    if (a === null) return null;
    return legalSourcesForInput(spec(), registry, a.stepId, a.portName);
  });
  /**
   * Lookup keyed by source NODE id → its `LegalSource` for the armed port, so
   * a rendered leaf can ask "am I a legal bind target, and would it coerce?"
   * in O(1). First port wins if a node exposes several (the canvas binds to
   * that port; the dropdown is the surface for picking a specific one).
   * `$input` and container-seed sources have no leaf node, so they never key
   * here — they're reachable only via the dropdown, by design.
   */
  const armedLegalByNode = createMemo<Map<string, LegalSource> | null>(() => {
    const list = armedLegalSources();
    if (list === null) return null;
    const m = new Map<string, LegalSource>();
    for (const s of list) if (!m.has(s.node)) m.set(s.node, s);
    return m;
  });
  // Esc disarms a pending wire. Registered once (the body reads no signals, so
  // the effect doesn't re-run); the handler reads `armed()` at event time.
  createEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape" && armed() !== null) disarmPort();
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => window.removeEventListener("keydown", onKey));
  });

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

  // Disarm any pending wire when the spec changes (4d-bis). Same reason as the
  // inspector reset above: an armed `{stepId, portName}` from a prior spec can
  // collide with a same-named leaf in the new one (AES-128 → AES-192 both have
  // `round.1.mix-columns`), silently re-activating the arm against a different
  // cipher. Clear on any spec-id change.
  createEffect(
    on(
      () => spec().id,
      () => disarmPort(),
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

  /**
   * The active spec's persisted USER layout, or null if none yet — ONLY the
   * localStorage/user entry (dragged pins, collapses, replication/stroke
   * overrides). Gates user-customization affordances (the reset button's
   * `disabled` state) and the manual `strokeStyles` reader; NOT what rendering
   * reads (that's `effectiveLayout()`). Formerly named `activeLayout`; split
   * from the curated-default fallback in Part B (graph-legibility plan).
   */
  const userLayout = createMemo(() => {
    const m = layoutMap();
    return m[spec().id] ?? null;
  });

  /**
   * Whether this spec has a curated default layout (a shipped built-in
   * arrangement). Drives the reset-button split: with a curated default the
   * toolbar offers "reset to default" + "reset to automatic"; without one it
   * keeps today's single "reset layout". EMPTY catalogue in B1, so this is
   * `false` for every shipped spec until later Part B chunks author layouts.
   */
  const hasCuratedDefault = createMemo(() => curatedDefaultFor(spec().id) !== null);

  /**
   * The layout that actually drives RENDERING: the user layout overlaid on the
   * curated default (user wins per id, via `mergeLayoutSpecs`). Falls back to
   * pure user (or pure curated, or null) at the edges. "Reset to automatic"
   * suppresses the curated fallback for this spec (session-only signal), so a
   * suppressed spec renders from the user layout alone.
   *
   * The curated default is a pure read-time fallback — never persisted — so
   * spec-only-save byte-stability is untouched. Persistence baselines read the
   * raw `layoutMap` entry (the store setters), never this merged value, so the
   * first drag on a curated spec persists only the dragged node.
   *
   * Curated layouts are authored at the canonical `normal` density and rescaled
   * to the current density HERE (`scaleCuratedLayout`), because they never enter
   * `layoutMap` and so escape `rescaleAllPositions`. The scale runs on the
   * curated layout ALONE, before the user layout merges on top — user pins are
   * already at the current density (rescaled on every flip), so scaling the
   * merged result would double-scale them. Reading `density()` here keeps the
   * memo reactive to a density flip. `factor === 1` (normal) is a no-op.
   */
  const effectiveLayout = createMemo(() => {
    const user = userLayout();
    if (isCuratedLayoutSuppressed(spec().id)) return user;
    const rawCurated = curatedDefaultFor(spec().id);
    if (!rawCurated) return user;
    const curated = scaleCuratedLayout(rawCurated, DENSITY_SCALE[density()] / DENSITY_SCALE.normal);
    if (!user) return curated;
    return mergeLayoutSpecs(curated, user);
  });

  /**
   * Spec-author-declared default-collapsed container ids (Slice 2.6d
   * follow-up, 2026-05-25). Walked once per spec change via
   * `getDefaultCollapsedContainers`. SHA-256 returns 64 ids; every
   * other shipped cipher returns the empty set. Threaded into both
   * the effective `collapsedSet` (below) and the chevron's toggle
   * handler so a single click correctly routes through
   * `toggleCollapse(..., inDefaults)`.
   */
  const defaultCollapsedSet = createMemo<ReadonlySet<string>>(() =>
    getDefaultCollapsedContainers(spec()),
  );

  /**
   * Effective collapsed set: (spec defaults ∪ layout.collapsedGroups) −
   * layout.expandedGroups. Memoized so re-derives only when the spec
   * or the persisted layout changes.
   *
   * Pre-2.6d-follow-up this was just `new Set(l.collapsedGroups)`; the
   * spec-defaults layer was added so SHA-256's 64 round groups render
   * collapsed on first visit without writing to localStorage (the
   * byte-stability discipline forbade the seed-on-first-render
   * alternative). The new `expandedGroups` set lets the user override
   * the spec defaults explicitly, and `toggleCollapse` preserves the
   * "id never in both sets" end-invariant.
   */
  const collapsedSet = createMemo<ReadonlySet<string>>(() =>
    getEffectiveCollapsedSet(spec(), effectiveLayout()),
  );

  /**
   * Every container id in the spec, document order (nested included). Drives
   * the toolbar's "collapse all" / "expand all" buttons — both their bulk
   * store calls and their disabled state. Re-derives only on spec change.
   */
  const allContainerIds = createMemo<readonly string[]>(() => getAllContainerIds(spec()));

  /**
   * True when the spec has ≥1 container that is NOT currently collapsed — i.e.
   * "collapse all" has work to do. False when there are no containers or all
   * are already collapsed (button disabled).
   */
  const hasExpandedContainer = createMemo<boolean>(() =>
    allContainerIds().some((id) => !collapsedSet().has(id)),
  );

  /**
   * True when the spec has ≥1 container that IS currently collapsed — i.e.
   * "expand all" has work to do. False when there are no containers or none
   * are collapsed (button disabled).
   */
  const hasCollapsedContainer = createMemo<boolean>(() =>
    allContainerIds().some((id) => collapsedSet().has(id)),
  );

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

  /**
   * Raw pin map for the active spec — every position stored in the
   * `LayoutSpec`. Consumers that participate in layout should read
   * `pinnedMap` (the orphan-filtered view declared after `graph()`)
   * instead; only callers that need the unfiltered set (drag handlers
   * recording new pins, persistence inspectors) should reach for this.
   */
  const rawPinnedMap = createMemo<ReadonlyMap<string, { x: number; y: number }>>(() => {
    const l = effectiveLayout();
    if (!l) return new Map();
    const m = new Map<string, { x: number; y: number }>();
    for (const [id, p] of Object.entries(l.positions)) m.set(id, p);
    return m;
  });

  /**
   * Per-id relative-pin map for the active spec (draggable-replicas plan,
   * 2026-05-19). Keyed by synthetic id (`${source}@->${consumer}` for aux
   * replicas, `${iterateId}@block${i}` for block chips); value is the
   * `(dx, dy)` delta from the algorithm's auto-laid position. Empty when
   * no chip has been dragged.
   *
   * Unlike `pinnedMap`, this memo does NOT filter orphan ids: synthetic
   * ids are regenerated every layout pass from the post-replication
   * graph, so an entry whose corresponding chip isn't currently rendered
   * just falls through harmlessly — the layout engine's per-id
   * `relativePins.get(id)` lookup returns `undefined` and no delta is
   * applied. Same "no pruning of stale ids" policy as the absolute pin
   * map (cf. `layout.ts` header).
   */
  const relativePinsMap = createMemo<ReadonlyMap<string, { dx: number; dy: number }>>(() => {
    const l = effectiveLayout();
    if (!l || !l.relativePositions) return new Map();
    const m = new Map<string, { dx: number; dy: number }>();
    for (const [id, r] of Object.entries(l.relativePositions)) m.set(id, r);
    return m;
  });

  /**
   * Per-source replication overrides for the active spec. Plain object so
   * it can be passed straight to `replicateHighFanoutSources` without a
   * Map ↔ object conversion at the boundary.
   */
  const replicationModes = createMemo<{ readonly [sourceId: string]: "always" | "never" }>(() => {
    const l = effectiveLayout();
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

      /**
       * Walk a node to find its anchor for the endpoint-pill arrow.
       *
       * Container descent (2026-05-20 fix): without this, the AES-128
       * output anchor lands on the `round-10` GROUP, making the spine
       * arrow read `round-10-container → ciphertext` instead of the
       * pedagogically correct `round.10.add-round-key → ciphertext`.
       * `s.steps`'s top-level walk identified round-10 as a state
       * consumer (containers always are) and stopped at the container
       * boundary; the fix recurses to find the deepest last
       * state-consuming LEAF.
       *
       * Per-container-kind rules:
       *
       *   - `step` (leaf): return its id when it's a state consumer;
       *     null when it's aux-only (skip and let the caller continue
       *     searching at sibling level).
       *   - `group`: transparent — recurse on children in `direction`
       *     order, return the first non-null match.
       *   - `iterate`: return the iterate id directly. The spine
       *     terminates at the iterate boundary (per
       *     `[[feedback-state-spine-no-phantoms]]`) — the inner body
       *     doesn't expose a spine-successor leaf that an outer edge
       *     could land on; the iterate's id IS the boundary.
       *   - `feistel-round`: for the OUTPUT side, return the rejoin
       *     synthetic id (`${id}:rejoin`) — that's the round's
       *     spine-exit point (see `processFeistelRound` in graph.ts).
       *     For the INPUT side, descend into the first non-empty
       *     track's first leaf — fan-in from the predecessor lands
       *     there per the same function. If every track is empty,
       *     fall back to the rejoin synthetic.
       *
       * Why mirror these to the existing inferStateEdges semantics:
       * the endpoint pill's edge needs to land on the same node the
       * normal-spine edge would land on if there were a sibling
       * predecessor/successor. Otherwise the pill arrow would draw to
       * a node that the next/prev-sibling-edge inference doesn't
       * agree with — confusing geometry.
       */
      const findAnchor = (node: StepNode, direction: "first" | "last"): string | undefined => {
        if (node.kind === "step") return isStateConsumer(node) ? node.id : undefined;
        if (node.kind === "iterate") return node.id;
        // Group: recurse on children in `direction` order.
        const children = direction === "last" ? [...node.children].reverse() : node.children;
        for (const child of children) {
          const anchor = findAnchor(child, direction);
          if (anchor !== undefined) return anchor;
        }
        return undefined;
      };

      let input: string | undefined;
      let output: string | undefined;
      for (const n of s.steps) {
        const a = findAnchor(n, "first");
        if (a !== undefined) {
          input = a;
          break;
        }
      }
      for (let i = s.steps.length - 1; i >= 0; i--) {
        const n = s.steps[i];
        if (!n) continue;
        const a = findAnchor(n, "last");
        if (a !== undefined) {
          output = a;
          break;
        }
      }
      return { input, output };
    },
  );

  /**
   * Endpoint pill labels. Three branches:
   *   - Hash specs (SHA-256 shipped 2026-05-25): "message" → "digest".
   *     Hashes are direction-less; `mode()` is semantically inert in the
   *     hash spec store, so we short-circuit on `isHash(algorithm())`
   *     BEFORE the encrypt/decrypt dispatch.
   *   - Cipher encrypt: "plaintext" → "ciphertext".
   *   - Cipher decrypt: labels swap ("ciphertext" → "plaintext"). The
   *     layout / spec direction itself does NOT mirror — decryption
   *     flows left-to-right with the inverse round body, only the I/O
   *     labels swap. This matches the 2026-05-15 design decision
   *     (memory: feedback_graph_design_decisions).
   *
   * Mirrors the `inputLabel()` / `outputLabel()` pattern shipped in
   * `App.tsx` (~line 1061) so the linear sidebar and graph endpoint
   * pills agree on what the user is putting in and getting out.
   *
   * **Future seams.** MACs use `message` / `tag`; KDFs use
   * `ikm + salt + info` / `okm`; AEAD ciphers have TWO outputs
   * (ciphertext + tag). Each new category gets its own branch here
   * when the first spec lands. Memory pointer: [[project_hash_future]].
   */
  const endpointLabels = createMemo<{ inputLabel: string; outputLabel: string }>(() => {
    const algo = useAlgorithm()();
    if (isHash(algo)) {
      return { inputLabel: "message", outputLabel: "digest" };
    }
    // RSA (asymmetric): encrypt consumes the message m → ciphertext c; decrypt
    // consumes c → m. Matches App.tsx's inputLabel()/outputLabel() so the graph
    // endpoint pills agree with the linear sidebar.
    if (isAsymmetric(algo)) {
      return useMode()() === "encrypt"
        ? { inputLabel: "message", outputLabel: "ciphertext" }
        : { inputLabel: "ciphertext", outputLabel: "message" };
    }
    return useMode()() === "encrypt"
      ? { inputLabel: "plaintext", outputLabel: "ciphertext" }
      : { inputLabel: "ciphertext", outputLabel: "plaintext" };
  });

  /**
   * Root-level leaves that don't consume cipher state. These get lifted
   * above the spine row by `layoutRoot` so the synthetic plaintext-pill →
   * first-state-consumer arrow doesn't visually pass through them.
   *
   * Two paths to qualify:
   *
   * 1. **Legacy / lifted-ported** — `shapeContract.input === "any"`.
   *    Today's examples: `aes.key-expansion@1`, `generic.iv-load@1`,
   *    `generic.aux-load@1`, `generic.state-to-aux-bytes@1`.
   * 2. **Port-native pure source** (universal-port-dataflow plan, Phase 2+):
   *    THREE conditions, all required —
   *      a. `kind: "ported"` registration.
   *      b. `meta` declares neither `stateInputPort` nor
   *         `stateOutputPort` — the step neither reads nor writes the
   *         spine state variable.
   *      c. The spec leaf declares no `portInputs` — i.e. it's a true
   *         source in the spec-edge graph, not a port-chain consumer.
   *    Today's examples: `constant-load@1` and `aux-load-bytes@1` at the
   *    SHA-256 preamble row (`H-constant`, `K-to-aux`, `H-to-aux`). The
   *    legacy heuristic skipped these because port-native step types
   *    omit `shapeContract` — fixed S2(d) of
   *    `docs/plans/sha-256-density-polish.md`, 2026-05-26.
   *
   * **Why each condition matters:**
   *
   * - The `stateInputPort` / `stateOutputPort` check excludes the
   *   genuine state bridges. `bytes-to-state@1` has no spec-time
   *   `portInputs` (the runtime projects its input via
   *   `meta.stateOutputPort`) but it WRITES state; lifting it would
   *   break the spine.
   * - The `portInputs`-empty check excludes port-chain CONSUMERS.
   *   `pad-with-byte@1` and `append-be64-length@1` are port-native with
   *   no state-port meta, but they declare spec-level `portInputs`
   *   (`pad`'s input wires to `plaintext-source.output`); they're
   *   downstream nodes in a port-flow chain, not sources. Without this
   *   check the SHA-256 spec's `pad` and `length-append` would
   *   incorrectly lift to the top row alongside the actual constant
   *   emitters. (Advisor-flagged fallout from S2(d) original ship,
   *   tightened same day.)
   *
   * No-contract LEGACY leaves stay on the spine — they might consume
   * state, we can't tell, and a wrong lift is more jarring than a missed
   * one. The port-native branch is safe to widen because port-native
   * step types declare their state involvement explicitly via `meta`
   * AND their port-graph involvement explicitly via `portInputs`.
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
      // Path 1 — legacy/lifted-ported shapeContract.
      const contract = registry.getDoc(n.type)?.shapeContract;
      if (contract && contract.input === "any") {
        out.add(n.id);
        continue;
      }
      // Path 2 — port-native pure source. Three conjuncts — see the
      // memo doc above for why each one is load-bearing. Reading
      // `meta` and `portInputs` is safe across both shapes: legacy
      // registrations have no `meta`, the access is undefined, and the
      // predicate short-circuits; `portInputs` is optional on every
      // step leaf, so the absent-or-empty check works uniformly.
      const reg = registry.getRegistration(n.type);
      const hasPortInputs = n.portInputs !== undefined && Object.keys(n.portInputs).length > 0;
      if (
        reg?.kind === "ported" &&
        reg.meta?.stateInputPort === undefined &&
        reg.meta?.stateOutputPort === undefined &&
        !hasPortInputs
      ) {
        out.add(n.id);
      }
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
      initialState: { shape: "bytes" as const, bytes: new Uint8Array(0) },
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
      // Slice S2(f), 2026-05-26 — pass the registry so the per-edge gate
      // can suppress the legacy consecutive-siblings state-spine inference
      // for any leaf that declares `portInputs` (pure port-native OR
      // hybrid-ported with an explicit state-port override). Port-flow edges
      // from `inferPortEdges` (S2(e)) own the spine on those specs. Since
      // Slice 5.3b EVERY shipped cipher/hash is port-wired (SHA-256, native-AES,
      // AES-CBC, DES, Speck, Serpent), so the gate fires for all of them and
      // `inferStateEdges` no longer owns any shipped spine.
      registry,
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
   *
   * (Pre-5.3e an `auxOnlyFilteredGraph` stage sat here, running
   * `dropAuxOnlyStateEdges` to suppress the legacy identity-passthrough
   * spine edge out of aux-only roots like `key-expansion`. With the legacy
   * `inferStateEdges` consecutive-siblings inference retired in Slice 5.3e
   * the spine is pure port-flow — no such passthrough edge is ever emitted
   * — so the filter and the `auxOnlyRootSinkIds` memo it consumed were
   * removed. `auxOnlyRootIds` SURVIVES: it still drives the layout-lift of
   * aux-only roots off the spine row in `layoutRoot`.)
   */
  /**
   * Twofish canonical rounds are self-contained 4-rail cells; their internal
   * leaves must NOT be replicated. The round split feeds 6 port-flow edges
   * (each of its first two outputs drives both a g function AND a carried
   * recombine input, plus the R2/R3 rails) — over the fanout threshold — so
   * without this it would scatter into per-consumer chips and break the cell +
   * the swap-X edge detection. (DES/Blowfish splits stay under the threshold,
   * so they never hit this.) We mark every recognized-round member `"never"`.
   * Computed straight from `spec()` — not the later `twofishRoundsById` memo —
   * to avoid a temporal-dead-zone reference from this earlier pipeline stage.
   * The high-fanout KEY-SCHEDULE publish source is NOT a round member, so it
   * still replicates its 40 subkey loads as intended.
   */
  const twofishRoundNeverModes = createMemo<{ readonly [id: string]: "never" }>(() => {
    const modes: Record<string, "never"> = {};
    // Gated on the canonical-layout hatch: with the 4-rail cell OFF (default),
    // the round renders as a generic stack, so its split SHOULD replicate like
    // any other high-fanout source — no cell to protect. Matches the original
    // pre-4-rail behavior for the A/B comparison.
    if (!isTwofishCanonicalEnabledForLayout()) return modes;
    const walk = (nodes: readonly StepNode[]): void => {
      for (const node of nodes) {
        if (node.kind === "step") continue;
        if (node.kind === "group") {
          const shape = analyzeTwofishRound(node);
          if (shape !== null) {
            for (const id of [
              shape.splitId,
              shape.recombineId,
              shape.rolNodeId,
              ...shape.g0Ids,
              ...shape.g1Ids,
              ...shape.phtIds,
              ...shape.r2MixIds,
              ...shape.r3MixIds,
            ]) {
              modes[id] = "never";
            }
          }
        }
        walk(node.children);
      }
    };
    walk(spec().steps);
    return modes;
  });

  /**
   * Canonical Feistel rounds (DES + Blowfish) are self-contained two-column
   * cells; their internal leaves must NOT scatter into per-consumer replica
   * chips. Blowfish's `splitF` fans out to four S-box lookups (fanout 4 > the
   * threshold 3), so without this it replicates into four chips that pile onto
   * one cell — the "enormous amount of split-F replicas on top of one another"
   * the user reported. Marking every recognized-round member `"never"` keeps
   * `splitF` a single node drawing four short edges to its S-boxes. DES has no
   * high-fanout round member, so this is a provable no-op there (verified via
   * the layout box-dump: DES's only replica is the key-schedule aux source,
   * which is NOT a round member and still replicates one chip per round).
   */
  const feistelRoundNeverModes = createMemo<{ readonly [id: string]: "never" }>(() => {
    const modes: Record<string, "never"> = {};
    const walk = (nodes: readonly StepNode[]): void => {
      for (const node of nodes) {
        if (node.kind === "step") continue;
        if (node.kind === "group") {
          const shape = analyzeFeistelRound(node);
          if (shape !== null) {
            for (const id of [
              shape.splitId,
              shape.fxorId,
              shape.recombineId,
              ...shape.fStackIds,
              ...shape.railNodeIds,
            ]) {
              modes[id] = "never";
            }
          }
        }
        walk(node.children);
      }
    };
    walk(spec().steps);
    return modes;
  });

  /**
   * ARX double rounds are self-contained two-tier cells, and their split is the
   * most extreme fan-out source in the app — see `arxRoundNeverModes` in
   * `core/arx-group.ts` for the measured consumer counts and what happens
   * without the guard. It lives there, not here, so the replication tests can
   * drive the SAME function this component does rather than a local paraphrase
   * of it.
   */
  const arxNeverModes = createMemo<{ readonly [id: string]: "never" }>(() =>
    arxRoundNeverModes(spec()),
  );

  const replicatedGraph = createMemo<CipherGraph>(() =>
    replicate()
      ? replicateHighFanoutSources(expandedGraph(), replicationThreshold(), {
          // Round members first so a user's explicit per-source override
          // (rare on a round-internal split) still wins on top.
          ...twofishRoundNeverModes(),
          ...arxNeverModes(),
          ...feistelRoundNeverModes(),
          ...replicationModes(),
        })
      : expandedGraph(),
  );

  /** Final display graph. Identity over `replicatedGraph`. Kept as a
   * separate memo so downstream code that subscribes to `graph()` doesn't
   * have to be re-pointed every time the pipeline shifts. */
  const graph = createMemo<CipherGraph>(() => replicatedGraph());

  /**
   * Orphan-filtered pin map for layout consumers.
   *
   * **Slice 7b (2026-05-17).** When a user flips a source's replication to
   * `"always"`, the source is removed from the post-replication graph and
   * replaced by replicas with synthetic ids (`${src}@->${consumer}`).
   * Replica ids are not stable across reruns and the source's stored pin
   * has no honest target to migrate to — so we silently DROP orphan pins
   * on read. The localStorage entry is preserved, which means flipping
   * the override back to `"auto"` / `"never"` restores both the original
   * chip AND its pinned position in one step (no manual re-pin needed).
   *
   * Dev diagnostic: one `console.debug` per orphan id, gated on
   * `import.meta.env.DEV`, so an engineer flipping `"always"` on doesn't
   * wonder why their dragged-position vanished — but prod stays quiet.
   * The `debuggedOrphanPins` Set lives in component scope so the message
   * fires once per id per session (re-firing on every memo recompute
   * would spam).
   */
  const debuggedOrphanPins = new Set<string>();
  const pinnedMap = createMemo<ReadonlyMap<string, { x: number; y: number }>>(() => {
    const raw = rawPinnedMap();
    if (raw.size === 0) return raw;
    const g = graph();
    const liveIds = new Set<string>();
    for (const n of g.nodes) liveIds.add(n.stepId);
    for (const c of g.containers) liveIds.add(c.id);
    let droppedAny = false;
    const filtered = new Map<string, { x: number; y: number }>();
    for (const [id, p] of raw) {
      if (!liveIds.has(id)) {
        droppedAny = true;
        if (import.meta.env.DEV && !debuggedOrphanPins.has(id)) {
          debuggedOrphanPins.add(id);
          console.debug(
            `[GraphView] dropping orphan layout pin for "${id}" — not in post-replication graph (likely a fully-replicated source).`,
          );
        }
        continue;
      }
      filtered.set(id, p);
    }
    // Identity short-circuit so layout-pass memos don't reactively
    // recompute when no pins were filtered.
    return droppedAny ? filtered : raw;
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
   * Bundled view of `graph()` — same-(from, to, kind, isFeedback) edges
   * collapsed into `EdgeBundle`s for render-time visual decongestion.
   *
   * Motivating case (2026-05-17 manual smoke): AES-128 ECB with iterate
   * COLLAPSED + key-expansion source set to "always" replicate produced
   * 11 parallel aux arrows fanning into the iterate. Post-bundle: one
   * thicker arrow with a `×11` label. Singleton bundles (`auxKeys
   * .length === 1`) render IDENTICALLY to the pre-bundle world — same
   * data-edge-key format, same stroke width — so every non-bundled
   * spec/iterate state is byte-identical to before.
   *
   * Recomputed when either `graph()` or `feedbackPredicate()` changes;
   * since `feedbackPredicate` already depends on `graph()`, the effective
   * trigger is `graph()` identity.
   */
  const bundledGraph = createMemo(() => bundleEdges(graph(), feedbackPredicate()));

  /**
   * Two-pass paint partition of `bundledGraph().bundles`. Both arrays are
   * recomputed only when `bundledGraph()` identity changes — a cheap
   * single-pass split.
   *
   * **Why two passes:** SVG paints in document order, so the canvas
   * body is laid out as `containers → edges → leaves` precisely so
   * leaves cover the edge tails/heads that tuck under their box fills
   * (clean arrowhead alignment). Feedback edges (cross-iteration aux —
   * today only CBC's `cbc-snapshot → cbc-xor`, more arrive with OFB /
   * CFB) are the one case where this hurts: a feedback edge has to
   * arc backwards across the round body to reach its earlier
   * consumer, and any unrelated node it crosses obscures it.
   *
   * Splitting the partition here keeps the 95%+ of bundles in their
   * original position (preserving the tuck for forward edges) and lifts
   * just the feedback bundles into a second `<For>` rendered AFTER the
   * leaves. The arrowhead now lands ON TOP of the consumer leaf instead
   * of tucking under; with `stroke-opacity: 0.55` + dashed (see
   * `.graph-edge-feedback` in `app.css`) this reads as "subtle line
   * overlapping the box", not "arrow stuck on the front face".
   *
   * Surfaced by manual smoke on AES-128 CBC 2026-05-18: feedback arrow
   * passed behind `round.0.add-round-key` and reappeared at the
   * `cbc-xor` consumer.
   */
  const nonFeedbackBundles = createMemo(() => bundledGraph().bundles.filter((b) => !b.isFeedback));
  const feedbackBundles = createMemo(() => bundledGraph().bundles.filter((b) => b.isFeedback));

  /**
   * Sources eligible for a row in the override panel: any id appearing in
   * `edge.from` for at least one fanout-eligible edge in the collapsed
   * graph. Sorted by fanout descending so the high-fanout offenders
   * surface first. Includes both leaf stepIds and iterate-container ids.
   *
   * Fanout-eligibility predicate mirrors `replicateHighFanoutSources`
   * exactly (graph.ts:2118): `kind: "aux"` OR (`kind: "state"` AND
   * `auxKey === PORT_FLOW_AUX_KEY`). Slice S2(i) widened the replication
   * predicate to count port-flow state edges; this panel-inclusion memo
   * was missed at the time, so SHA-256's port-native sources
   * (e.g. `fetch-p2` with 3 outgoing port-flow edges to
   * `sigma1-r17/r19/s10`) wouldn't surface in the override panel even
   * though they ARE eligible for the actual replication transform.
   * Fixed 2026-05-26 same-day after Slice S2(l) ship surfaced the gap.
   *
   * Legacy passthrough state edges (`kind: "state"`, `auxKey: "state"`)
   * stay excluded — they're 1-to-1 between consecutive same-parent
   * leaves and would inflate the panel with every spine participant
   * (same reasoning as in `replicateHighFanoutSources`).
   *
   * Includes single-edge sources (fanout = 1). A user with a long arrow
   * crossing the canvas may want to replicate even a one-consumer source
   * to shorten that arrow — the original `fanout >= 2` cutoff hid that
   * use case. The visual cost is a longer override panel; tradeoff
   * favored the discoverability of "any fanout-eligible edge can be
   * locally replicated".
   */
  const replicationSources = createMemo<{ readonly id: string; readonly fanout: number }[]>(() => {
    const g = collapsedGraph();
    // DISTINCT CONSUMERS per source — mirrors `replicateHighFanoutSources`'s
    // metric exactly (graph.ts, 2026-06-02). The transform makes one replica
    // per (source, consumer) pair, so the panel's "N edges" count must be
    // distinct consumers, not raw edges, or the displayed number would
    // disagree with what "always"/threshold actually does (most visibly in
    // the collapsed-group→collapsed-iterate corner, where many edges fold
    // onto one consumer and the honest fan-target count is 1).
    const consumers = new Map<string, Set<string>>();
    for (const e of g.edges) {
      const eligible = e.kind === "aux" || (e.kind === "state" && e.auxKey === PORT_FLOW_AUX_KEY);
      if (!eligible) continue;
      let set = consumers.get(e.from);
      if (!set) {
        set = new Set<string>();
        consumers.set(e.from, set);
      }
      set.add(e.to);
    }
    const rows: { id: string; fanout: number }[] = [];
    for (const [id, set] of consumers) {
      if (set.size >= 1) rows.push({ id, fanout: set.size });
    }
    rows.sort((a, b) => b.fanout - a.fanout || a.id.localeCompare(b.id));
    return rows;
  });

  // ─── Source-color coding (2026-05-19) ──────────────────────────────────
  //
  // Per-source color assignment for the graph view. The auto-color map is
  // derived deterministically from `graph()` (alphabetical sort over
  // every non-pill canonical source, palette-then-HSL — see
  // `core/source-colors.ts`). Manual user overrides win over auto.
  // Single-fanout sources participate (post-2026-05-19 — user-asked).
  //
  // Memo deps:
  //   - `graph()`: rerun whenever the graph rewires (spec edit, replicate
  //     toggle, collapse). Necessary AND sufficient for `autoSourceColors`
  //     because the helper only reads structure.
  //   - `manualSourceColors()`: per-spec map from the override store —
  //     reactivity wires through `useManualSourceColors(specId)`. The
  //     value memo recomposes when the override map for the active
  //     spec.id changes.
  //
  // Why two separate memos: keeps the auto pass cheap to re-run on every
  // graph change (small allocation, single pass) and the combined map
  // cheap to re-run on every override change (one Map clone + N writes).
  // A single fused memo would re-allocate the auto map every time a
  // manual override flipped.
  const sourceColoringEnabled = useSourceColoringEnabled();
  const includeSingleSources = useIncludeSingleSources();
  // Per-spec fanout threshold (2026-07-10): SHA-256 defaults to 1 (colour
  // every source), every other built-in to 3. Tracks the active spec id so a
  // cipher switch re-reads the correct default.
  const colorThreshold = useColorThreshold(() => spec().id);
  const manualSourceColors = useManualSourceColors(() => spec().id);
  const colorsPanelOpen = useColorsPanelOpen(() => spec().id);
  // Auto-color map honours the user-set fanout threshold (2026-05-30). At
  // the default (3) only sources fanning out to ≥ 3 consumers auto-colour;
  // at 0/1 every source does → every edge gets a colour.
  const autoSourceColors = createMemo(() => assignSourceColors(graph(), colorThreshold()));
  // Combined map (auto + manual) — what the renderer reads. Empty when
  // the master toggle is OFF, so the EdgePath fallback to kind-based
  // styling takes over automatically.
  const effectiveSourceColors = createMemo(() => {
    if (!sourceColoringEnabled()) return EMPTY_COLOR_MAP;
    const auto = autoSourceColors();
    const manual = manualSourceColors();
    if (manual.size === 0) return auto;
    const merged = new Map(auto);
    for (const [k, v] of manual) merged.set(k, v);
    return merged;
  });

  // ─── Source-STROKE coding (Part A / chunk A3a, 2026-07-09) ───────────────
  //
  // The second disambiguation channel alongside colour: a per-source dash
  // *style* (see `core/source-strokes.ts`). Mirrors the colour memos above,
  // with two deliberate differences (both documented on the store,
  // `view-source-strokes.ts`):
  //
  //   1. **Threshold is OWNED, not reused (2026-07-10).** `assignSourceStrokes`
  //      walks `multiFanoutSources(graph, strokeThreshold())` with the stroke
  //      channel's OWN per-spec threshold — the user split it from the colour
  //      threshold so the two counters move independently. The (colour, dash)
  //      index pairing is therefore no longer locked; that's the accepted
  //      trade-off for independent cutoffs.
  //   2. **Manual overrides come from `LayoutSpec.strokeStyles`**, not a
  //      viewer store — arrow styles TRAVEL with the document (the divergence
  //      from colours). We read them off `userLayout()` so the memo
  //      recomputes when the persisted layout changes (a `setSourceStroke`
  //      write replaces the layout entry).
  //
  // Per-spec master toggle AND per-spec threshold (SHA-256 ships ON with
  // threshold 1 → every source styled; every other built-in OFF, threshold 3 —
  // see `view-source-strokes.ts`). Both track the active spec id, so switching
  // cipher re-reads the correct defaults.
  const strokeStylingEnabled = useSourceStrokeStylingEnabled(() => spec().id);
  const strokeThreshold = useStrokeThreshold(() => spec().id);
  const autoSourceStrokes = createMemo(() => assignSourceStrokes(graph(), strokeThreshold()));
  // Manual per-source style-name overrides, read off the active layout's
  // `strokeStyles` map (absent → empty). Tracks `userLayout()`, so a
  // `setSourceStroke` write (which mints a new layout entry) recomputes this.
  const manualSourceStrokes = createMemo<ReadonlyMap<string, string>>(() => {
    // Reads the USER layout (not the merged/effective one): curated defaults
    // carry NO strokeStyles — SHA-256's per-source dashes come from A3b's
    // auto-assignment (`view-source-strokes` ships it ON), so there is nothing
    // for a curated layout to contribute here, and keeping this on the user
    // entry avoids a curated stroke reappearing after a manual clear.
    const styles = userLayout()?.strokeStyles;
    if (styles === undefined) return EMPTY_STROKE_MAP;
    return new Map(Object.entries(styles));
  });
  // Combined map (auto + manual) of canonical source id → style NAME — what
  // the per-edge resolver reads. Empty when the master toggle is OFF, so the
  // EdgePath fall-through to un-styled edges takes over automatically.
  const effectiveSourceStrokes = createMemo<ReadonlyMap<string, string>>(() => {
    if (!strokeStylingEnabled()) return EMPTY_STROKE_MAP;
    const auto = autoSourceStrokes();
    const manual = manualSourceStrokes();
    if (manual.size === 0) return auto;
    const merged = new Map(auto);
    for (const [k, v] of manual) merged.set(k, v);
    return merged;
  });

  // List of rows for the SourceColorsPanel. Each row carries:
  //   - `id`: canonical source id.
  //   - `color`: the effective colour (`undefined` for single-fanout
  //     sources without a manual override — rendered with a hatched
  //     swatch indicating "click to assign").
  //   - `fanout`: outgoing-edge count (replicas roll up to canonical).
  //   - `isManual`: whether a user override is in effect (drives the
  //     [reset] button visibility).
  //   - `isAutoColored`: whether the source has an auto-assigned
  //     palette colour. False for single-fanout sources; true for
  //     multi-fanout. Used to decide whether the swatch starts
  //     coloured or hatched.
  //
  // Listing scope (post-2026-05-19):
  //   - master toggle OFF → empty list (panel hidden).
  //   - master ON, include-single OFF (default) → multi-fanout only.
  //   - master ON, include-single ON → every source emitting any
  //     outgoing edge.
  // Manual overrides for single-fanout sources always show in the
  // list regardless of the sub-toggle, so the user can find what they
  // previously coloured even when the sub-toggle is off (otherwise
  // their override would be invisible in the panel but still active
  // on the canvas).
  //
  // A3b (2026-07-09): this panel now hosts BOTH per-source channels —
  // colour swatch AND stroke-style dropdown — so each row also carries the
  // stroke fields (`strokeName` = effective name, `autoStrokeName` = the
  // auto-assigned name for the dropdown's "auto (…)" option, `isStrokeManual`
  // = a manual override is in effect). The id set unions manual STROKE keys
  // too: a source with a manual stroke, no colour override, and sub-threshold
  // fanout must still surface a row, else its override is invisible and
  // unresettable (the same invariant the colour manual keys satisfy).
  const sourceColorRows = createMemo<
    readonly {
      id: string;
      color: string | undefined;
      fanout: number;
      isManual: boolean;
      isAutoColored: boolean;
      strokeName: string | undefined;
      autoStrokeName: string | undefined;
      isStrokeManual: boolean;
    }[]
  >(() => {
    const auto = autoSourceColors();
    const manual = manualSourceColors();
    const autoStrokes = autoSourceStrokes();
    const manualStrokes = manualSourceStrokes();
    const includeSingle = includeSingleSources();
    // Reuse `replicationSources` style fanout counting — single pass over
    // the graph's edges, replicas counted toward their canonical source.
    const fanout = new Map<string, number>();
    const g = graph();
    const replicaOf = new Map<string, string | undefined>();
    for (const node of g.nodes) replicaOf.set(node.stepId, node.replicaOf);
    for (const e of g.edges) {
      const canonical = replicaOf.get(e.from) ?? e.from;
      fanout.set(canonical, (fanout.get(canonical) ?? 0) + 1);
    }
    // Decide which ids to surface:
    //   - Multi-fanout always (via `auto.keys()`; auto strokes share the
    //     same key set, so `auto.keys()` already covers auto-styled sources).
    //   - Anything with a manual colour OR manual stroke override (so the
    //     user's previous picks remain visible / resettable).
    //   - Every other source when the sub-toggle is ON.
    const ids = new Set<string>([...auto.keys(), ...manual.keys(), ...manualStrokes.keys()]);
    if (includeSingle) {
      for (const id of allColorableSources(g)) ids.add(id);
    }
    const rows: {
      id: string;
      color: string | undefined;
      fanout: number;
      isManual: boolean;
      isAutoColored: boolean;
      strokeName: string | undefined;
      autoStrokeName: string | undefined;
      isStrokeManual: boolean;
    }[] = [];
    for (const id of ids) {
      const manualColor = manual.get(id);
      const autoColor = auto.get(id);
      const manualStroke = manualStrokes.get(id);
      const autoStroke = autoStrokes.get(id);
      rows.push({
        id,
        color: manualColor ?? autoColor,
        fanout: fanout.get(id) ?? 0,
        isManual: manualColor !== undefined,
        isAutoColored: autoColor !== undefined,
        strokeName: manualStroke ?? autoStroke,
        autoStrokeName: autoStroke,
        isStrokeManual: manualStroke !== undefined,
      });
    }
    rows.sort((a, b) => a.id.localeCompare(b.id));
    return rows;
  });

  // `layout` is declared below, AFTER `portAssignment`, because the
  // layout pass takes a `portAssignment` argument (used to shift a
  // single-replica chip's x for a vertical arrow into the consumer).
  // Solid memos run their body once on creation to capture deps, so
  // forward-referencing `portAssignment` here would TDZ-fault. Moving
  // the declaration is the cleanest fix — no other consumers between
  // here and `portAssignment` need `layout()`.

  /**
   * Port-spreading follow-up to Slice 7c (2026-05-16): the per-component
   * `ReplicaPlacement` memo, computed independently from `layoutRoot` so
   * the edge `<For>` block can read `sourceOf` + `rowOfSource` for the
   * `consumerPortOffset` / `replicaSourceXOffset` helpers. Cheap to
   * recompute (single pass over `graph().nodes` + `graph().edges`);
   * memoizes against `graph()` identity so reruns only happen when the
   * graph itself swaps. We don't return this from `layoutRoot` to avoid
   * widening the pure-helper contract — `layoutRoot`'s consumers (test
   * suites, future codegen) don't need it.
   */
  const replicaPlacement = createMemo(() => buildReplicaPlacement(graph()));

  /**
   * Focus-dim v0 (Slice S2(m) of sha-256-density-polish, 2026-05-26 —
   * selection-only). When the user has a NODE selected via the value
   * inspector, every non-incident edge is dimmed to ~0.18 opacity so
   * the incident arrows pop visually. Address: SHA-256's high-fanout
   * consumers (`final.assemble`'s 8 incoming port-flow edges, expanded
   * msg-schedule's 3–4-input combines like `sigma1` / `w-t`) where
   * even after S2(j)/(j2)/(k) the steady-state read still feels
   * crowded. Now interactive: click the consumer chip → its incoming
   * arrows pop.
   *
   * Three memos:
   *   - `focusedNodeId` — extracts the node id from `selectedTarget`,
   *     null when no node is selected (edge / bundle / nothing).
   *   - `focusedIncidentIds` — the focused id PLUS every replica whose
   *     canonical source is the focused id. So clicking the canonical
   *     `K-to-aux` chip OR any of its `K-to-aux@->round.X` replicas
   *     highlights ALL related arrows. Without this expansion the
   *     replica edges (whose `from` is the synth id, not the canonical)
   *     would dim alongside everything else, which is pedagogically
   *     wrong.
   *   - `focusDimActive` — true ONLY when at least one edge is
   *     incident. Guards the block-chip case: clicking a block chip
   *     sets `selectedTarget.id = "${iterateId}@block${i}"` (a synth
   *     id with no edges), which without this guard would dim
   *     everything ("no incident edge" → "the predicate dims all").
   *     Falling back to "no dim" preserves the existing scrub + halo
   *     behavior on block chips.
   *
   * Selection-only by design (v0); a follow-up slice may add hover-
   * primary plumbing on chip pointer events. Per advisor:
   * selection-only ships with ~10 lines instead of ~30+ pointer
   * handlers across 5 render paths, no pan/drag gate needed, no
   * jsdom-vs-browser pointer-event discrepancy to verify. The spec.id
   * watcher above (line ~2283) already clears `selectedTarget` on
   * cipher swap, so a stale focused id can't leak across specs.
   */
  const focusedNodeId = createMemo<string | null>(() => {
    const t = selectedTarget();
    return t !== null && t.kind === "node" ? t.id : null;
  });

  const focusedIncidentIds = createMemo<ReadonlySet<string> | null>(() => {
    const focused = focusedNodeId();
    if (focused === null) return null;
    const ids = new Set<string>([focused]);
    // Replica expansion: walk every node, include any whose
    // `replicaOf` field points at the focused id. Covers BOTH
    // spine-replicas and aux fan-out replicas — `replicaPlacement.
    // sourceOf` only captures the latter (its build pass at
    // `buildReplicaPlacement` line ~928 skips spine-replicas with
    // `continue`), but a spine-replica's outgoing edge still carries
    // its synth `${src}@->${consumer}` id as `edge.from` and the
    // user pedagogically wants its dim state tied to the canonical
    // source the same as an aux replica. `graph().nodes` is the
    // authoritative replica list since every replica chip is added
    // there by the replication pass.
    for (const node of graph().nodes) {
      if (node.replicaOf === focused) ids.add(node.stepId);
    }
    return ids;
  });

  const focusDimActive = createMemo<boolean>(() => {
    const ids = focusedIncidentIds();
    if (ids === null) return false;
    // Bail out when the focused id has no incident edges (block-chip
    // synth ids, orphan-id selections, future chip kinds with no
    // graph representation). Otherwise the dim predicate would tag
    // every edge, fading the entire canvas.
    for (const edge of graph().edges) {
      if (ids.has(edge.from) || ids.has(edge.to)) return true;
    }
    return false;
  });

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
   * Containers sorted by `containerPath.length` ascending so PARENT
   * containers paint FIRST (deeper in document order → drawn first in
   * SVG) and CHILD containers paint LAST (drawn on top). Without this
   * sort, an outer group (e.g. DES's `Rounds`) whose entry in
   * `graph().containers` happened to come AFTER its children's entries
   * would have its `<rect>` painted over its children's rects,
   * obliterating any visual treatment on the inner containers
   * (Phase 6e smoke 2026-05-20: the individual feistel-round borders
   * were entirely hidden behind the Rounds group's neutral rect).
   * Stable sort: equal-depth siblings keep their original relative
   * order, which preserves the layout-pin reset affordance's
   * deterministic position rule.
   */
  const containersInPaintOrder = createMemo(() => {
    const list = [...graph().containers];
    list.sort((a, b) => a.containerPath.length - b.containerPath.length);
    return list;
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
   * Per-consumer port-slot assignment memo
   * (port-spreading-consumer-head plan, 2026-05-16; visual-target
   * bucketing followup 2026-05-17). Reads the same `graph()` identity
   * as `replicaPlacement` and composes with it (the builder needs
   * `rowOfSource` to align slot ordering with source-side vertical
   * staggering). The `visualEdgeTargetId` callback ensures retargeted
   * replica edges (those whose visual landing point differs from raw
   * `edge.to` — e.g. replica → iterate, retargeted to the iterate's
   * first non-replica body step per the slice-2 anchor) bucket WITH
   * same-visual-target direct edges (e.g. replica → first-body-step
   * directly). Without this, the renderer would render a retargeted
   * edge and a direct edge to the same visual node at the same x
   * (offset 0 in their separate single-incoming and small-bucket-midpoint
   * buckets) → visible collision. Declared AFTER `nodesById` and
   * `containersById` because Solid's createMemo runs its body eagerly
   * on construction (TDZ would fire if those memos weren't defined yet).
   */
  // Baseline layout — same `layoutRoot` call as the final layout below
  // but WITHOUT a `portAssignment`, so no single-replica chip x-shift
  // is applied. Used solely as a source-x lookup for the port
  // assignment's leftmost-source-wins comparator (2026-05-17 fix for
  // non-replica fan-IN crossings — see `buildConsumerPortAssignment`
  // doc-block).
  //
  // **No feedback loop**: the final `layout` reads `portAssignment`,
  // which reads `baseLayout`, which is computed WITHOUT
  // `portAssignment` — so the chain terminates after one extra
  // `layoutRoot` call per reactive tick. The single-replica x-shift
  // only nudges a chip by one `portGap` (~13 px at normal density);
  // that's not enough to flip the relative left/right order of two
  // sources whose natural-position x values are determined by the
  // spec walk, so re-running port-assignment against the post-shift
  // layout would produce the same slot ordering. We don't iterate.
  // `baseLayout` deliberately OMITS portAssignment AND relativePins — it
  // exists only as a source-x lookup table for the leftmost-source-wins
  // comparator used inside the port-assignment builder. Including either
  // would create a feedback loop (port assignment depends on base layout,
  // base layout would then depend on port assignment) without changing
  // the lookup's correctness in any cipher we've shipped or planned.
  // Feistel-shaped round groups in the active spec (id → derived shape),
  // driving the canonical two-column Feistel layout in `layoutNode`. Derived
  // purely from each group's wiring via `analyzeFeistelRound` — DES rounds
  // today; any split→F→xor→concat group qualifies, no cipher tag. The outer
  // `rounds` group (bodyOutput → a child GROUP) and AES/Serpent/SHA rounds
  // (bodyOutput → a non-concat leaf) return null and keep the generic layout.
  const feistelRoundsById = createMemo(() => {
    const m = new Map<string, FeistelRoundShape>();
    const walk = (nodes: readonly StepNode[]): void => {
      for (const node of nodes) {
        if (node.kind === "step") continue;
        if (node.kind === "group") {
          const shape = analyzeFeistelRound(node);
          if (shape !== null) m.set(node.id, shape);
        }
        walk(node.children);
      }
    };
    walk(spec().steps);
    return m;
  });

  // Twofish 4-rail round shapes, keyed by group id — the parallel of
  // `feistelRoundsById`. A group recognized by `analyzeTwofishRound` triggers
  // the canonical 4-rail layout (Twofish's round is NOT the 2-way Feistel form,
  // so it has its own recognizer/layout).
  const twofishRoundsById = createMemo(() => {
    const m = new Map<string, TwofishRoundShape>();
    // Canonical 4-rail layout is OFF by default (`?twofish4rail=1` to enable);
    // an empty map means no round is recognized, so every Twofish round falls
    // through to the generic vertical-stack layout — the "original" view.
    if (!isTwofishCanonicalEnabledForLayout()) return m;
    const walk = (nodes: readonly StepNode[]): void => {
      for (const node of nodes) {
        if (node.kind === "step") continue;
        if (node.kind === "group") {
          const shape = analyzeTwofishRound(node);
          if (shape !== null) m.set(node.id, shape);
        }
        walk(node.children);
      }
    };
    walk(spec().steps);
    return m;
  });

  // ARX double-round shapes (ChaCha20 or Salsa20), keyed by group id — the
  // third member of the canonical-layout family. Unlike Twofish there is no
  // opt-in hatch: the
  // two-tier quarter-round grid is always on, because the alternative for a
  // 98-leaf ARX group is a vertical ribbon with no structure at all, and there
  // is no "original" view worth preserving for an A/B comparison.
  const arxRoundsById = createMemo(() => arxDoubleRoundsById(spec()));

  // `baseLayout` passes feistelRounds (so the source-x lookup matches the final
  // layout for Feistel round leaves) but still OMITS portAssignment +
  // relativePins — passing `undefined` lets layoutRoot's defaults apply.
  const baseLayout = createMemo(() =>
    layoutRoot(
      graph(),
      pinnedMap(),
      consts(),
      auxOnlyRootIds(),
      undefined,
      undefined,
      feistelRoundsById(),
      twofishRoundsById(),
      arxRoundsById(),
    ),
  );

  const portAssignment = createMemo(() => {
    // Port-assignment is now keyed off BUNDLES (one slot per bundle) so an
    // 11-auxKey bundle counts as one incoming edge at its consumer
    // instead of 11. The builder consumes a CipherGraph; pass a thin
    // structural shim whose `edges` array is the bundles' representative
    // edges. Render-time helpers look up the same `bundle
    // .representativeEdge` reference, so identity-based map keys
    // (`slotOf.get(edge)`) hit. State edges are singleton bundles in
    // practice, so the assignment is byte-identical for the non-bundled
    // case.
    const bg = bundledGraph();
    // Track which representative edges are feedback. Bundles carry the
    // flag; the synth graph's `edges` array is just the representative
    // edges, so we build a parallel side-table for the `sideOf`
    // callback to consult below.
    const isFeedbackByRep = new Map<GraphEdge, boolean>();
    const repEdges: GraphEdge[] = [];
    for (const b of bg.bundles) {
      isFeedbackByRep.set(b.representativeEdge, b.isFeedback);
      repEdges.push(b.representativeEdge);
    }
    const synthGraph: CipherGraph = {
      nodes: bg.nodes,
      containers: bg.containers,
      edges: repEdges,
      rootIds: bg.rootIds,
    };
    const boxes = baseLayout().boxes;
    const visualTargetOf = (e: GraphEdge): string =>
      visualEdgeTargetId(e, nodesById(), containersById());
    // Side classification matches `EdgePath`'s `geom()` regime detection
    // (search for "Three regimes" in this file). The render layer
    // dispatches the path shape off the same geometric test, so any
    // future change to one MUST change the other in lockstep. The
    // 2026-05-19 fix for "the last arrow in each AES round group reads
    // as crooked" comes from this side-aware bucketing — vertical-
    // regime state-spine arrows on a consumer's TOP edge stop sharing
    // a slot pool with horizontal-regime aux arrows on the same
    // consumer's LEFT edge.
    const sideOf = (e: GraphEdge): "top" | "bottom" | "left" | "right" | undefined => {
      // Feedback edges always route over the top (per `EdgePath`'s
      // overhead-arc branch). The arc enters the target's TOP edge,
      // regardless of source position.
      if (isFeedbackByRep.get(e) === true) return "top";
      const fromBox = boxes.get(e.from);
      const toBox = boxes.get(visualTargetOf(e));
      // No layout info → fall through to consumer-keyed bucketing for
      // this edge. Returning undefined preserves the today-behaviour
      // path inside the builder.
      if (fromBox === undefined || toBox === undefined) return undefined;
      const horizOverlap =
        Math.min(fromBox.x + fromBox.w, toBox.x + toBox.w) > Math.max(fromBox.x, toBox.x);
      const vertOverlap =
        Math.min(fromBox.y + fromBox.h, toBox.y + toBox.h) > Math.max(fromBox.y, toBox.y);
      if (horizOverlap && !vertOverlap) {
        // Vertical regime: target enters TOP edge when source is above,
        // BOTTOM edge when source is below.
        const downward = toBox.y + toBox.h / 2 >= fromBox.y + fromBox.h / 2;
        return downward ? "top" : "bottom";
      }
      // Horizontal regime: target enters LEFT edge when source is to
      // the left, RIGHT edge when source is to the right.
      const rightward = fromBox.x + fromBox.w / 2 <= toBox.x + toBox.w / 2;
      return rightward ? "left" : "right";
    };
    return buildConsumerPortAssignment(
      synthGraph,
      replicaPlacement(),
      visualTargetOf,
      // Source-x lookup for the leftmost-source-wins comparator. Returns
      // undefined for sources not in the layout (replica canonical
      // sources after Slice 7b — they're removed from `nodes`), which
      // makes the comparator fall through to row-based ordering for
      // those edges.
      (canonicalSource) => boxes.get(canonicalSource)?.x,
      sideOf,
    );
  });

  // Producer-side port assignment — the outgoing-edge mirror of
  // `portAssignment`. Spreads a multi-out source's N tails across its exit
  // edge so they leave from N distinct points instead of stacking at one
  // centre (e.g. AES `key-expansion` → 11 round keys with replication OFF).
  // Built off the SAME bundled graph + baseline layout so the per-edge
  // identity map keys line up with the render loop's `representativeEdge`,
  // and so it never feeds `layout` (no feedback loop — producer offsets only
  // shift attach points, never box positions).
  const producerAssignment = createMemo(() => {
    const bg = bundledGraph();
    const isFeedbackByRep = new Map<GraphEdge, boolean>();
    const repEdges: GraphEdge[] = [];
    for (const b of bg.bundles) {
      isFeedbackByRep.set(b.representativeEdge, b.isFeedback);
      repEdges.push(b.representativeEdge);
    }
    const synthGraph: CipherGraph = {
      nodes: bg.nodes,
      containers: bg.containers,
      edges: repEdges,
      rootIds: bg.rootIds,
    };
    const boxes = baseLayout().boxes;
    const visualTargetOf = (e: GraphEdge): string =>
      visualEdgeTargetId(e, nodesById(), containersById());
    // Producer exit side — the SOURCE's perspective of the same geometry
    // `EdgePath`'s `geom()` uses to pick where the tail leaves the source
    // box (search "Three regimes"). Vertical regime → source exits BOTTOM
    // when the target is below, TOP when above. Horizontal regime → source
    // exits RIGHT when the target is to the right, LEFT when to the left.
    // Feedback edges leave the source's TOP edge (`sy = from.y`).
    const sideOf = (e: GraphEdge): "top" | "bottom" | "left" | "right" | undefined => {
      if (isFeedbackByRep.get(e) === true) return "top";
      const fromBox = boxes.get(e.from);
      const toBox = boxes.get(visualTargetOf(e));
      if (fromBox === undefined || toBox === undefined) return undefined;
      const horizOverlap =
        Math.min(fromBox.x + fromBox.w, toBox.x + toBox.w) > Math.max(fromBox.x, toBox.x);
      const vertOverlap =
        Math.min(fromBox.y + fromBox.h, toBox.y + toBox.h) > Math.max(fromBox.y, toBox.y);
      if (horizOverlap && !vertOverlap) {
        const downward = toBox.y + toBox.h / 2 >= fromBox.y + fromBox.h / 2;
        return downward ? "bottom" : "top";
      }
      const rightward = fromBox.x + fromBox.w / 2 <= toBox.x + toBox.w / 2;
      return rightward ? "right" : "left";
    };
    // Cross-axis sort coordinate: vertical exits (top/bottom) spread along
    // X → order by the target's centre X; horizontal exits (left/right)
    // spread along Y → order by the target's centre Y. Lets each tail leave
    // in its target's direction so the fan-out doesn't cross at the source.
    const targetCoordOf = (e: GraphEdge): number | undefined => {
      const b = boxes.get(visualTargetOf(e));
      if (b === undefined) return undefined;
      const side = sideOf(e);
      return side === "top" || side === "bottom" ? b.x + b.w / 2 : b.y + b.h / 2;
    };
    return buildProducerPortAssignment(synthGraph, targetCoordOf, sideOf);
  });

  // Now that `portAssignment` is declared, we can build `layout` —
  // see the placeholder comment higher up for why this lives here.
  const layout = createMemo(() =>
    layoutRoot(
      graph(),
      pinnedMap(),
      consts(),
      auxOnlyRootIds(),
      portAssignment(),
      relativePinsMap(),
      feistelRoundsById(),
      twofishRoundsById(),
      arxRoundsById(),
    ),
  );

  /**
   * Inter-round Feistel SWAP (the "X"). The straight round→round carry edge
   * (`round.N.recombine → round.{N+1}.split`) between two Feistel rounds is
   * suppressed from the normal edge render (`visibleNonFeedbackBundles`) and
   * redrawn as two crossing wires by the overlay below — the canonical
   * depiction that the right half (R) becomes the next round's LEFT and (L⊕F)
   * becomes its RIGHT. `feistelCarryKeys` is the suppression set; `feistelSwaps`
   * is the geometry. The crossing is driven by the SOURCE round's `swap` flag
   * (read from its recombine argument order), so editing a round to (no-)swap
   * flips the picture live — and DES's round 16 (no successor round) simply has
   * no inter-round swap drawn.
   */
  const feistelCarryKeys = createMemo(() => {
    const rounds = feistelRoundsById();
    if (rounds.size === 0) return new Set<string>();
    const recombineIds = new Set<string>();
    const splitIds = new Set<string>();
    for (const shape of rounds.values()) {
      recombineIds.add(shape.recombineId);
      splitIds.add(shape.splitId);
    }
    // Suppress the plain carry edge ONLY where the swap X actually replaces it —
    // i.e. vertically-stacked rounds (DES). Gated on the SAME geometric test as
    // `feistelSwaps` below so the two never disagree (a mismatch would either
    // double-draw the carry edge or drop it). Horizontally-tiled Blowfish rounds
    // fail the test → their carry edge is kept and routes like any other edge.
    const boxes = layout().boxes;
    const keys = new Set<string>();
    for (const e of graph().edges) {
      if (!recombineIds.has(e.from) || !splitIds.has(e.to)) continue;
      const rb = boxes.get(e.from);
      const sb = boxes.get(e.to);
      if (rb === undefined || sb === undefined) continue;
      if (!feistelRoundsStackVertically(rb, sb)) continue;
      // NUL separator: can't collide with any character in a step id. Written
      // as the \u0000 escape (NOT a raw NUL byte) so the file stays text to
      // grep/diff tools — a literal NUL makes ripgrep classify it as binary.
      keys.add(`${e.from}\u0000${e.to}`);
    }
    return keys;
  });

  /**
   * Where each leaf's input-port wiring dot should sit, AND the colour it should
   * take: the box-edge point where that port's incoming arrow actually arrives,
   * tinted to match that arrow (2026-07-12). Keyed `consumerStepId → (portName →
   * { x, y, color })`; a port with no resolvable incoming edge (unbound, or fed
   * from the plaintext pill / a container seed — the pill sits to the LEFT so the
   * left-edge fallback already aligns) is simply absent, and `LeafRect` falls
   * back to the legacy muted left-edge placement for it.
   *
   * **Two edge classes resolve to a port** (the user's "arrows must land on the
   * dots in ALL cases"):
   *   - **Port-flow spine** (`kind:"state"`, `auxKey === PORT_FLOW_AUX_KEY`) —
   *     the edge's `toPort` names the consumer input port directly.
   *   - **Aux fan-in** (`kind:"aux"`, e.g. a round key / P-array subkey / S-box
   *     table) — the edge carries an `auxKey` but NO `toPort`, so we resolve it
   *     through the consumer leaf's `meta.auxReadPorts(params)` reverse map
   *     (`auxKey → input-port name`). This is what pulls the gold P[i] / round-key
   *     operand dot off the left edge and onto its arrowhead.
   *
   * **We iterate the raw MEMBER edges (`bg.edges`), not `bg.bundles`.** Several
   * ports can share one rendered arrow: when the SAME source feeds two ports of
   * the SAME consumer (Twofish `split → recombine.input2` + `.input3`, or
   * `g1 → dbl2T1.operand0` + `.operand1` for `2·T1`), those edges collapse into
   * one `(from,to,kind)` bundle drawn as a single `×N` arrow. Reading only the
   * representative's `toPort` would leave every non-representative port dot
   * stranded on the left edge. So we walk each member edge, resolve its own port,
   * and land it at the BUNDLE's arrival point (computed once from the
   * representative — the geometry `EdgePath` actually draws) so the co-fed ports
   * stack their dots on the shared arrowhead.
   *
   * Geometry comes from the SAME inputs `EdgePath` uses for the target attach —
   * the `layout()` boxes, the bundle representative edge, and `consumerPortOffset`
   * against `portAssignment()` — so a dot lands exactly on its arrow's head. The
   * two `consumerPortOffset` calls mirror the `targetXOffset` (vertical regime:
   * LEAF_W-scaled gap) and `targetYOffset` (horizontal regime: LEAF_H-scaled gap)
   * memos in `renderBundle`; `portArrivalPoint` then selects whichever axis the
   * regime uses. The colour comes from `arrivalColorFor` against the SAME
   * `effectiveSourceColors` map `renderBundle` feeds its `sourceColor` prop.
   */
  const portArrivalPoints = createMemo<
    ReadonlyMap<string, ReadonlyMap<string, { x: number; y: number; color: string }>>
  >(() => {
    const result = new Map<string, Map<string, { x: number; y: number; color: string }>>();
    const boxes = layout().boxes;
    const assign = portAssignment();
    const c = consts();
    const bg = bundledGraph();
    const nById = nodesById();
    const cById = containersById();
    const sourceColors = effectiveSourceColors();
    const isFb = feedbackPredicate();
    // Gap/cap pairs copied from `renderBundle`'s targetXOffset / targetYOffset.
    const vGap = Math.max(6, Math.round(c.LEAF_W / 10));
    const vCap = c.LEAF_W / 2 - 4;
    const hGap = Math.max(4, Math.round(c.LEAF_H / 4));
    const hCap = c.LEAF_H / 2 - 4;

    // Reverse map per aux-reading leaf: `auxKey → input-port name`. Only leaves
    // whose registration declares `meta.auxReadPorts` project an aux read onto a
    // named input port (the port-native idiom, e.g. `xor-with-aux`'s `operand`,
    // `blowfish.sbox-lookup`'s table ports); a legacy executor-only `auxReads`
    // has no port to land on and is intentionally out of scope.
    const auxPortByLeaf = new Map<string, Map<string, string>>();
    for (const [id, node] of nById) {
      const readPorts = registry.getRegistration(node.stepType)?.meta?.auxReadPorts;
      if (readPorts === undefined) continue;
      // A REPLICA reproduces its source leaf, so its params (hence its
      // `auxReadPorts` mapping) live on the source — the replica id itself is
      // NOT in the spec. Resolve `replicaOf` first so an aux-fed replicated
      // loader (RSA's high-fanout `load-n@->square-0` / `load-exp@->…`, one
      // per square-and-multiply rung) still maps `aux[rsa.n] → input` and lands
      // a dot. Port-flow replicas already resolved (their dot rides `toPort`,
      // which needs no spec lookup); this generalizes that to aux-fed ones.
      const leaf = findStep(spec(), node.replicaOf ?? id);
      if (leaf === null) continue;
      const rev = new Map<string, string>();
      for (const [port, auxKey] of readPorts(leaf.params)) rev.set(auxKey, port);
      auxPortByLeaf.set(id, rev);
    }

    // Bundle lookup so a member edge can borrow its bundle's representative edge
    // (the one `EdgePath` actually draws) for geometry + isFeedback. Keyed via
    // the SHARED `bundleKeyFor` so a member edge finds its OWN bundle — port-flow
    // rails split by `toPort` in `bundleEdges`, so a `(from,to,kind,fb)`-only key
    // would collide the per-port bundles (RSA `result-seed → square-0.a`/`.b`,
    // `eea-i → eea-i+1` on r/newR/t/newT) and strand every sibling port's dot on
    // the survivor's arrowhead.
    const bundleByKey = new Map<string, EdgeBundle>();
    for (const b of bg.bundles) {
      bundleByKey.set(bundleKeyFor(b.representativeEdge, b.isFeedback), b);
    }
    // Arrival point per bundle (representative geometry), computed once + cached.
    const pointByBundle = new Map<EdgeBundle, { x: number; y: number } | null>();
    const bundleArrival = (b: EdgeBundle, targetId: string): { x: number; y: number } | null => {
      const cached = pointByBundle.get(b);
      if (cached !== undefined) return cached;
      const to = boxes.get(targetId);
      const from = boxes.get(b.representativeEdge.from);
      const point =
        to === undefined || from === undefined
          ? null
          : portArrivalPoint(from, to, {
              isFeedback: b.isFeedback,
              targetXOffset: consumerPortOffset(b.representativeEdge, assign, vGap, vCap),
              targetYOffset: consumerPortOffset(b.representativeEdge, assign, hGap, hCap),
            });
      pointByBundle.set(b, point);
      return point;
    };

    // Place one port's dot at its bundle's arrowhead, tinted to the arrow. First
    // writer wins — a declared input port has exactly one incoming arrow.
    const place = (targetId: string, portName: string, edge: GraphEdge) => {
      const fb = isFb(edge);
      const b = bundleByKey.get(bundleKeyFor(edge, fb));
      if (b === undefined) return;
      const point = bundleArrival(b, targetId);
      if (point === null) return;
      let inner = result.get(targetId);
      if (inner === undefined) {
        inner = new Map();
        result.set(targetId, inner);
      }
      if (inner.has(portName)) return;
      inner.set(portName, { ...point, color: arrivalColorFor(edge, sourceColors, nById) });
    };

    // A round→round carry that the Feistel swap-X replaces (DES) draws its own
    // per-rail landing dots (`graph-feistel-swap-dot`), so skip the plain
    // input-port dot for it — otherwise the split shows a single dot at the
    // suppressed edge's geometry, coloured by `recombine` (often the grey
    // palette slot) and NOT under either visible swap wire.
    const carryKeys = feistelCarryKeys();
    for (const edge of bg.edges) {
      if (carryKeys.size > 0 && carryKeys.has(`${edge.from}\u0000${edge.to}`)) continue;
      const targetId = visualEdgeTargetId(edge, nById, cById);
      // Port-flow spine edge → `toPort` names the consumer input port directly.
      if (edge.kind === "state" && edge.auxKey === PORT_FLOW_AUX_KEY && edge.toPort !== undefined) {
        place(targetId, edge.toPort, edge);
        continue;
      }
      // Aux fan-in → resolve which declared input port this key fills.
      const portName = auxPortByLeaf.get(targetId)?.get(edge.auxKey);
      if (portName !== undefined) place(targetId, portName, edge);
    }
    return result;
  });

  /**
   * Case D (2026-07-12): arrival dots on COLLAPSED containers. A collapsed group
   * / iterate hides its internals, so an incoming arrow (SHA-256's per-round `W`
   * aux into a folded `round.N`, the `blocks → round.0` seed, the `blocks →
   * msg-schedule` history) lands on the container box with no terminus marker —
   * the case D of "every arrow should end on a colored dot". We place ONE
   * non-interactive dot per incoming rendered arrow (deduped by bundle) at the
   * point EdgePath actually attaches it, tinted to the arrow.
   *
   * Scoped to `collapsedSet()`: an EXPANDED container shows its children (and
   * their own port dots), and a dot on the big wrapper edge would be noise. Keyed
   * `containerId → { x, y, color }[]`. Geometry + colour mirror `portArrivalPoints`
   * exactly (same `consumerPortOffset` / `arrivalColorFor`), so a container dot and
   * its arrowhead never disagree.
   */
  const containerArrivalDots = createMemo<
    ReadonlyMap<string, { x: number; y: number; color: string }[]>
  >(() => {
    const collapsed = collapsedSet();
    const result = new Map<string, { x: number; y: number; color: string }[]>();
    if (collapsed.size === 0) return result;
    const boxes = layout().boxes;
    const cById = containersById();
    const nById = nodesById();
    const sourceColors = effectiveSourceColors();
    const bg = bundledGraph();
    const assign = portAssignment();
    const c = consts();
    const isFb = feedbackPredicate();
    const vGap = Math.max(6, Math.round(c.LEAF_W / 10));
    const vCap = c.LEAF_W / 2 - 4;
    const hGap = Math.max(4, Math.round(c.LEAF_H / 4));
    const hCap = c.LEAF_H / 2 - 4;
    // One dot per RENDERED arrow: dedup member edges down to their bundle.
    const seen = new Set<string>();
    for (const edge of bg.edges) {
      const targetId = visualEdgeTargetId(edge, nById, cById);
      if (!collapsed.has(targetId)) continue;
      const toBox = boxes.get(targetId);
      const fromBox = boxes.get(edge.from);
      if (toBox === undefined || fromBox === undefined) continue;
      const fb = isFb(edge);
      const bkey = bundleKeyFor(edge, fb);
      if (seen.has(bkey)) continue;
      seen.add(bkey);
      const point = portArrivalPoint(fromBox, toBox, {
        isFeedback: fb,
        targetXOffset: consumerPortOffset(edge, assign, vGap, vCap),
        targetYOffset: consumerPortOffset(edge, assign, hGap, hCap),
      });
      const dot = { ...point, color: arrivalColorFor(edge, sourceColors, nById) };
      const arr = result.get(targetId);
      if (arr === undefined) result.set(targetId, [dot]);
      else arr.push(dot);
    }
    return result;
  });

  /**
   * Canonical-Feistel decorations (DES canonical-representation feature):
   * per expanded Feistel round, the **L / R rail labels** under `split` and an
   * **F-function bounding box** around the F-stack column. Pure geometry read
   * off `layout().boxes` + the round's `FeistelRoundShape`. Collapsed rounds
   * (no child leaf boxes) are skipped. Rendered as a `pointer-events:none`
   * overlay so it never intercepts clicks/drags on the real leaves.
   */
  const feistelDecorations = createMemo(() => {
    const rounds = feistelRoundsById();
    if (rounds.size === 0) return [];
    const boxes = layout().boxes;
    const FBOX_PAD = 10;
    const out: {
      roundId: string;
      fBox: Box;
      lLabel: { x: number; y: number };
      rLabel: { x: number; y: number };
    }[] = [];
    for (const [roundId, shape] of rounds) {
      const splitB = boxes.get(shape.splitId);
      if (splitB === undefined) continue; // collapsed round → no leaf boxes.
      let minX = Number.POSITIVE_INFINITY;
      let minY = Number.POSITIVE_INFINITY;
      let maxX = Number.NEGATIVE_INFINITY;
      let maxY = Number.NEGATIVE_INFINITY;
      for (const fid of shape.fStackIds) {
        const b = boxes.get(fid);
        if (b === undefined) continue;
        minX = Math.min(minX, b.x);
        minY = Math.min(minY, b.y);
        maxX = Math.max(maxX, b.x + b.w);
        maxY = Math.max(maxY, b.y + b.h);
      }
      if (!Number.isFinite(minX)) continue;
      out.push({
        roundId,
        fBox: {
          x: minX - FBOX_PAD,
          y: minY - FBOX_PAD,
          w: maxX - minX + 2 * FBOX_PAD,
          h: maxY - minY + 2 * FBOX_PAD,
        },
        // L below split's left edge (the L rail drops left to fxor); R below
        // split's right edge (R forks right into the F function).
        lLabel: { x: splitB.x + 10, y: splitB.y + splitB.h + 18 },
        rLabel: { x: splitB.x + splitB.w - 10, y: splitB.y + splitB.h + 18 },
      });
    }
    return out;
  });

  const visibleNonFeedbackBundles = createMemo(() => {
    const carry = feistelCarryKeys();
    const bundles = nonFeedbackBundles();
    if (carry.size === 0) return bundles;
    return bundles.filter((b) => !carry.has(`${b.from}\u0000${b.to}`));
  });

  const feistelSwaps = createMemo(() => {
    const rounds = feistelRoundsById();
    if (rounds.size === 0) return [];
    const boxes = layout().boxes;
    const recombineToRound = new Map<string, FeistelRoundShape>();
    const splitToRound = new Map<string, FeistelRoundShape>();
    for (const shape of rounds.values()) {
      recombineToRound.set(shape.recombineId, shape);
      splitToRound.set(shape.splitId, shape);
    }
    const out: {
      id: string;
      swap: boolean;
      // Two ROLE-named wires with derived labels: `mixed` carries the combined
      // half (DES "L⊕F", Blowfish "R⊕F"), `carry` the pass-through half (DES
      // "R", Blowfish "L"). Origin/dest sides come from the round's orientation
      // so the crossing is byte-honest for both DES and the mirrored BF form.
      mixed: { x1: number; y1: number; x2: number; y2: number };
      carry: { x1: number; y1: number; x2: number; y2: number };
      mixedLabel: string;
      carryLabel: string;
      // Each rail is tinted by the SOURCE colour of the leaf that produced that
      // half (the mixed half comes from the round's `fxor`; the carried half from
      // its `split`, or the last pass-through rail node for Blowfish's `L⊕P[i]`).
      // This matches how `arrivalColorFor` colours every other arrival dot, so the
      // wire and the dot at its landing point agree — the pre-2026-07-12 wires were
      // a flat `var(--accent)` that clashed with the source-coloured split dot.
      mixedColor: string;
      carryColor: string;
      // Inspector edge keys (2026-07-13). Each swap wire REPLACES the suppressed
      // `recombine → split` carry edge, so the wires must be clickable → the value
      // inspector. Rather than point both at the 8-byte concat output (which would
      // contradict the per-half `R` / `L⊕F` labels), each wire keys the REAL
      // internal round edge that produced its half: the mixed wire → `fxor →
      // recombine` (its input port = `mixedRecombineInput`), the carry wire →
      // `carryProducer → recombine` (the COMPLEMENT input port). `encodeEdgeKey`
      // drops `fromPort`, so the carry wire — whose DES producer is the
      // multi-output `split` — resolves solely through `lookupRegularState`'s
      // port-specific branch on `toPort`; the complement port is therefore
      // load-bearing (a wrong port = a silent wrong-half value, no error).
      mixedEdgeKey: string;
      carryEdgeKey: string;
    }[] = [];
    const sourceColors = effectiveSourceColors();
    const railColor = (nodeId: string): string => sourceColors.get(nodeId) ?? "var(--accent)";
    const DX = 34; // horizontal offset of each half off the box center.
    for (const e of graph().edges) {
      const fromRound = recombineToRound.get(e.from);
      if (fromRound === undefined || !splitToRound.has(e.to)) continue;
      const rb = boxes.get(e.from);
      const sb = boxes.get(e.to);
      if (rb === undefined || sb === undefined) continue;
      // Same gate as `feistelCarryKeys`: only vertically-stacked rounds (DES) get
      // the swap X. Horizontally-tiled Blowfish rounds keep the plain carry edge
      // (which `feistelCarryKeys` correspondingly does NOT suppress for them).
      if (!feistelRoundsStackVertically(rb, sb)) continue;
      const labels = feistelValueLabels(fromRound);
      const wires = feistelSwapWires({
        // The fxor (combined half) sits LEFT when F is on the right (DES,
        // mixedHalf="L"), RIGHT when F is on the left (Blowfish, mixedHalf="R").
        mixedOriginSide: fromRound.mixedHalf === "L" ? "left" : "right",
        // Combined value lands in new_L (left) if it is the recombine's input0.
        mixedDestSide: fromRound.mixedRecombineInput === "input0" ? "left" : "right",
        recombineBox: rb,
        splitBox: sb,
        dx: DX,
      });
      // Carried-half producer: the last pass-through rail node if any (Blowfish's
      // `L⊕P[i]`), else the raw split output (DES).
      const carryProducer =
        fromRound.railNodeIds.length > 0
          ? (fromRound.railNodeIds[fromRound.railNodeIds.length - 1] as string)
          : fromRound.splitId;
      // The carried half lands on the recombine input the mixed half does NOT
      // occupy (a Feistel `concat` has exactly two inputs). This complement is
      // the whole game for the DES carry wire's lookup — see the type comment.
      const carryRecombineInput = fromRound.mixedRecombineInput === "input0" ? "input1" : "input0";
      out.push({
        id: `${e.from}->${e.to}`,
        swap: fromRound.swap,
        mixedLabel: labels.mixed,
        carryLabel: labels.carry,
        mixedColor: railColor(fromRound.fxorId),
        carryColor: railColor(carryProducer),
        // Real internal round edges (auxKey `port-flow`, kind `state`), so the
        // keys match the round's own `fxor → recombine` / `producer → recombine`
        // edges byte-for-byte and `lookupEdgeValue` resolves the correct half.
        mixedEdgeKey: encodeEdgeKey({
          from: fromRound.fxorId,
          to: fromRound.recombineId,
          auxKey: PORT_FLOW_AUX_KEY,
          kind: "state",
          toPort: fromRound.mixedRecombineInput,
        }),
        carryEdgeKey: encodeEdgeKey({
          from: carryProducer,
          to: fromRound.recombineId,
          auxKey: PORT_FLOW_AUX_KEY,
          kind: "state",
          toPort: carryRecombineInput,
        }),
        ...wires,
      });
    }
    return out;
  });

  /**
   * Canonical-Twofish decorations: per expanded Twofish round, a dashed "g"
   * bounding box around EACH of the two g-function stacks (the `rolR1` rail is
   * excluded — it sits atop the g1 box but is not part of g). Pure geometry off
   * `layout().boxes`; collapsed rounds are skipped. Overlay is
   * `pointer-events:none` so it never intercepts clicks on the real leaves.
   */
  const twofishDecorations = createMemo(() => {
    const rounds = twofishRoundsById();
    if (rounds.size === 0) return [];
    const boxes = layout().boxes;
    const GBOX_PAD = 10;
    const bboxOf = (ids: readonly string[]): Box | null => {
      let minX = Number.POSITIVE_INFINITY;
      let minY = Number.POSITIVE_INFINITY;
      let maxX = Number.NEGATIVE_INFINITY;
      let maxY = Number.NEGATIVE_INFINITY;
      for (const id of ids) {
        const b = boxes.get(id);
        if (b === undefined) continue;
        minX = Math.min(minX, b.x);
        minY = Math.min(minY, b.y);
        maxX = Math.max(maxX, b.x + b.w);
        maxY = Math.max(maxY, b.y + b.h);
      }
      if (!Number.isFinite(minX)) return null;
      return {
        x: minX - GBOX_PAD,
        y: minY - GBOX_PAD,
        w: maxX - minX + 2 * GBOX_PAD,
        h: maxY - minY + 2 * GBOX_PAD,
      };
    };
    const out: { roundId: string; g0Box: Box; g1Box: Box }[] = [];
    for (const [roundId, shape] of rounds) {
      const g0Box = bboxOf(shape.g0Ids);
      const g1Box = bboxOf(shape.g1Ids);
      if (g0Box === null || g1Box === null) continue; // collapsed round.
      out.push({ roundId, g0Box, g1Box });
    }
    return out;
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
   * Check whether a drag event carries a palette payload — a step type OR a
   * saved composite ("my elements"). `dataTransfer.types` is the only field
   * readable during `dragover` (`getData` is blocked outside `drop` for
   * security), so we sniff the MIME list to decide whether to call
   * `preventDefault` (which signals "this is a valid drop target" to the
   * browser). Both palette flavors must accept here, else the browser refuses
   * the composite drop.
   */
  const isPaletteDrag = (e: DragEvent): boolean => {
    const types = e.dataTransfer?.types;
    if (!types) return false;
    // `types` is a DOMStringList in some browsers; spread covers both.
    for (const t of types) {
      if (t === STEP_TYPE_DRAG_MIME || t === COMPOSITE_DRAG_MIME || t === "text/plain") return true;
    }
    return false;
  };

  const handleDragOver = (e: DragEvent): void => {
    if (!isPaletteDrag(e)) return;
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

  /**
   * Resolve the structural anchor a drop lands on — shared by the step-type
   * and composite (Phase 4f) drop paths, so both insert at the same place.
   *
   * Slice 5: gutter hit-test wins over the legacy data-drop-anchor walk. A
   * gutter under the cursor maps directly to a precise between-positions slot —
   * `before:X` (at-start / between siblings) or `after:Y` (at-end). Without
   * this priority a drop on the thin strip just above a leaf would resolve to
   * the leaf's anchor (insert AFTER the leaf) — the opposite of intent.
   *
   * Anchor-resolution dispatch (post-rescope, 2026-05-15): a CONTAINER anchor
   * (header band hit → lookup hit in `graph().containers`) routes to
   * `into-start` ("drop on header = enter this container's body"); a LEAF
   * anchor keeps the `after` semantic; no anchor → `root-append`.
   */
  const resolveDropAnchor = (e: DragEvent): CompositeInsertAnchor => {
    const target = e.target as Element | null;
    const gutterEl = target?.closest?.("[data-drop-gutter]") ?? null;
    const gutterEncoding = gutterEl?.getAttribute("data-drop-gutter") ?? null;
    if (gutterEncoding !== null) {
      // Encoding shape: `${"before" | "after" | "into-start"}:${siblingStepId}`.
      // Split on the FIRST colon only — step ids are forbidden from containing
      // colons by the runtime's `:b{i}` block-index suffix convention.
      const colonIdx = gutterEncoding.indexOf(":");
      if (colonIdx > 0) {
        const kind = gutterEncoding.slice(0, colonIdx);
        const targetId = gutterEncoding.slice(colonIdx + 1);
        if (kind === "before" && targetId.length > 0) return { kind: "before", stepId: targetId };
        if (kind === "after" && targetId.length > 0) return { kind: "after", stepId: targetId };
        // Empty-container sentinel gutter (see dropGutters memo): the entire box
        // of an empty container resolves here so the user can drop anywhere
        // inside the visible chip, not just the labelled header band.
        if (kind === "into-start" && targetId.length > 0) {
          return { kind: "into-start", containerId: targetId };
        }
      }
      // Malformed encoding — fall through to anchor / root-append.
    }
    // Walk up from the drop target to the nearest `data-drop-anchor`. `closest`
    // returns the element itself if it matches; replicas carry their source's
    // stepId, so the anchor is always a real spec id.
    const anchored = target?.closest?.("[data-drop-anchor]") ?? null;
    const anchorId = anchored?.getAttribute("data-drop-anchor") ?? null;
    if (anchorId !== null && anchorId.length > 0) {
      return containersById().get(anchorId) !== undefined
        ? { kind: "into-start", containerId: anchorId }
        : { kind: "after", stepId: anchorId };
    }
    return { kind: "root-append" };
  };

  const handleDrop = (e: DragEvent): void => {
    e.preventDefault();
    setDragOverActive(false);
    setDragOverAnchorId(null);
    setDragOverGutterId(null);
    if (!e.dataTransfer) return;

    // Composite drop (Phase 4f): a "my elements" entry carries its LIBRARY id
    // under the composite MIME (checked FIRST — composites carry no text/plain,
    // so this can't collide with the step-type path). Inline a fresh clone.
    const compositeId = e.dataTransfer.getData(COMPOSITE_DRAG_MIME);
    if (compositeId) {
      const def = getComposite(compositeId);
      if (def) insertCompositeIntoSpec(def.group, resolveDropAnchor(e));
      return;
    }

    // Step-type drop: prefer the custom MIME (palette-authored), fall back to
    // text/plain for browsers that strip non-standard MIMEs on DnD payloads.
    const stepType =
      e.dataTransfer.getData(STEP_TYPE_DRAG_MIME) || e.dataTransfer.getData("text/plain");
    if (!stepType || !registry.has(stepType)) return;
    insertStepIntoSpec(stepType, resolveDropAnchor(e));
  };

  /**
   * Begin a node drag on pointerdown. Works for any node id (container,
   * leaf, replica, block chip).
   *
   * Two modes:
   *   - **"absolute"** (default): pins the node's top-left in viewBox
   *     coordinates via `setNodePosition`. Used for containers and
   *     root-level non-replica leaves. Clamped to `(0, 0)` so a chip
   *     can't be dragged off the canvas edge and become unclickable.
   *   - **"relative"**: pins the node's delta from its auto-laid
   *     position via `setRelativePosition`. Used for synthetic-id chips
   *     (aux replicas, block chips) whose anchor is another node. NOT
   *     clamped — the auto position is already deep inside the canvas,
   *     so a user moving the chip toward the upper-left is a legitimate
   *     gesture. Added 2026-05-19 (draggable-replicas plan, Slice 3).
   *
   * Both modes use the same client-px-to-viewBox conversion (divide by
   * `zoom()`) and the same sub-threshold pointerup → `onClickFallback`
   * behavior so click-to-scrub on a draggable leaf still works.
   *
   * setPointerCapture is best-effort — jsdom older versions don't
   * implement it, but the window-level listeners below keep the drag
   * working either way.
   */
  const startNodeDrag = (
    nodeId: string,
    e: PointerEvent,
    onClickFallback?: () => void,
    opts: { mode: "absolute" | "relative" } = { mode: "absolute" },
  ): void => {
    e.stopPropagation();
    const startBox = layout().boxes.get(nodeId);
    if (!startBox) return;
    const startClientX = e.clientX;
    const startClientY = e.clientY;
    const startBoxX = startBox.x;
    const startBoxY = startBox.y;

    // Phase 6e fix for finding H(i): find the dragged node's parent
    // container so the move handler can clamp the pin to the parent's
    // interior bounds. Without this clamp, a feistel-round inside a
    // group container can be dragged anywhere on the canvas — including
    // off the parent's bottom edge — and become visually orphaned. The
    // clamp keeps the node visible inside its declared parent, which
    // matches the user's mental model ("the round belongs to Rounds").
    //
    // Only computed in absolute mode (the only mode that uses
    // setNodePosition); relative mode pins are deltas off the auto
    // position and rarely escape so far they need clamping.
    //
    // We scan `graph().containers` once at drag start (not per-move) and
    // capture the parent box + interior constants by value, so a child
    // pin update during the drag can't shift the clamp underneath us.
    // Root-level nodes have no parent — clamp falls back to the existing
    // (0, 0) SVG-bounds rule.
    let parentInteriorBounds: { minX: number; maxX: number; minY: number; maxY: number } | null =
      null;
    if (opts.mode === "absolute") {
      for (const candidate of graph().containers) {
        if (!candidate.childIds.includes(nodeId)) continue;
        const parentBox = layout().boxes.get(candidate.id);
        if (!parentBox) break;
        const PAD = consts().CONTAINER_PAD;
        parentInteriorBounds = {
          minX: parentBox.x + PAD,
          maxX: parentBox.x + parentBox.w - PAD - startBox.w,
          minY: parentBox.y + HEADER_H + PAD,
          maxY: parentBox.y + parentBox.h - PAD - startBox.h,
        };
        break;
      }
    }
    // Captured BEFORE the drag begins so accumulated deltas in relative
    // mode add to the existing pin (if any) rather than overwriting it.
    // Without this, dragging a chip that already had `dx = 30` would
    // reset to `dx = startCursorDelta` mid-gesture.
    const startRel = relativePinsMap().get(nodeId) ?? { dx: 0, dy: 0 };
    const startRelDx = startRel.dx;
    const startRelDy = startRel.dy;
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
      const z = zoom();
      if (opts.mode === "relative") {
        // Accumulate onto the start delta. No (0, 0) clamp: the chip's
        // auto-anchor is already deep in the canvas, and dragging
        // toward the upper-left is a valid gesture (the user might
        // want to move a high-fanout source chip up out of the row
        // it currently competes with).
        setRelativePosition(spec().id, nodeId, startRelDx + dx / z, startRelDy + dy / z);
      } else {
        // Clamp to (0, 0) so the block can't be dragged off the top or
        // left of the SVG. Negative SVG coordinates fall outside the
        // viewBox and are clipped by the browser — the block becomes
        // invisible AND unclickable. The bad position would also persist
        // in localStorage, making the block unreachable across reloads
        // until the user manually edits storage. At y >= 0 the block
        // stays inside the drawn area; even when the sticky header
        // (z-index: 1) visually overlays small SVG y values at
        // scrollTop > 0, scrolling the container back to the top always
        // reveals the block.
        let newX = Math.max(0, startBoxX + dx / z);
        let newY = Math.max(0, startBoxY + dy / z);
        // Phase 6e fix for finding H(i): if this node has a parent
        // container, additionally clamp the pin so the node stays inside
        // the parent's interior. Without this, dragging a feistel-round
        // inside the `Rounds` group could escape the parent entirely.
        // Belt-and-braces: take the tighter of (0, 0) and (parent.min) so
        // a parent whose box happens to start at negative coords still
        // sees the SVG-bounds floor honored.
        if (parentInteriorBounds) {
          newX = Math.max(parentInteriorBounds.minX, Math.min(parentInteriorBounds.maxX, newX));
          newY = Math.max(parentInteriorBounds.minY, Math.min(parentInteriorBounds.maxY, newY));
        }
        setNodePosition(spec().id, nodeId, newX, newY);
      }
    };

    const onUp = (): void => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
      // Close the undo gesture (C2): commits exactly ONE pre-drag entry iff the
      // layout map reference actually changed during the drag. A sub-threshold
      // click never moved a pin, so the map is untouched and no entry records —
      // the same `moved` outcome that drives `onClickFallback` below.
      endLayoutGesture();
      if (!moved && onClickFallback) onClickFallback();
    };

    // Open the undo gesture (C2) AFTER the `if (!startBox) return` guard above,
    // so a bailed drag never leaks the active flag. While the gesture is open,
    // the App-scope capture observer coalesces every per-pointermove layout
    // write into the single pre-drag snapshot committed by `endLayoutGesture`.
    beginLayoutGesture();
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
   *
   * Zoom anchoring (2026-05-18): the zoom focal point is the cursor
   * position, not a fixed origin. After the zoom delta is applied we
   * adjust the wrapper's scroll so the canvas point under the cursor
   * stays under the cursor — Figma / Google Maps convention.
   *
   * Math: viewBox-space cursor coords are constant across the gesture.
   *   vbX  = (clientX - svgRect.left) / oldZoom
   *   ΔscrollLeft = vbX × (newZoom - oldZoom)
   * Use `setViewZoom`'s RETURN value (post-clamp) for the delta, otherwise
   * an unclamped overshoot at the zoom-range edges drifts the anchor.
   *
   * Reflow trick: Solid mutates `width`/`height` synchronously when zoom
   * changes, but the browser defers layout until the next style recalc.
   * Setting `scrollLeft` before that recalc clamps to the STALE max
   * scrollable extent → visible anchor drift on zoom-in. Reading
   * `offsetWidth` forces a synchronous reflow so the scrollable extent
   * matches the new SVG size by the time we assign scroll positions.
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

    // Capture cursor anchor in viewBox-space BEFORE applying the new
    // zoom — `getBoundingClientRect()` reads the SVG's screen rect at
    // the current zoom, which is what `oldZoom` divides by. The wheel
    // listener fires on the wrapper (`ev.currentTarget`), so we have to
    // reach into it for the SVG element.
    const wrapperEl = scrollWrapperEl;
    const svgEl = wrapperEl?.querySelector("svg.graph-view-svg");
    if (!wrapperEl || !(svgEl instanceof SVGSVGElement)) {
      setViewZoom(spec().id, next);
      return;
    }
    const svgRect = svgEl.getBoundingClientRect();
    const vbX = (ev.clientX - svgRect.left) / current;
    const vbY = (ev.clientY - svgRect.top) / current;
    const oldScrollLeft = wrapperEl.scrollLeft;
    const oldScrollTop = wrapperEl.scrollTop;

    // Use the post-clamp value as the source of truth for the delta —
    // an unclamped overshoot at MIN/MAX would drift the cursor anchor.
    const clampedNext = setViewZoom(spec().id, next);
    const zoomDelta = clampedNext - current;
    if (zoomDelta === 0) return;

    // Force synchronous layout so the wrapper knows its new
    // scrollWidth/scrollHeight before we set the scroll target.
    // Otherwise zoom-in clamps to the stale max and the anchor drifts.
    void wrapperEl.offsetWidth;
    wrapperEl.scrollLeft = oldScrollLeft + vbX * zoomDelta;
    wrapperEl.scrollTop = oldScrollTop + vbY * zoomDelta;
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

  /**
   * Drag-to-pan the canvas (2026-05-18; rehomed to the scroll wrapper
   * 2026-05-30). Mousedown on the empty canvas background and drag
   * updates the wrapper's scroll position so the canvas slides under the
   * pointer — Figma / design-tool convention.
   *
   * Attach point: the handler lives on the `.graph-view` SCROLL WRAPPER,
   * not on the `<svg>`. The SVG is sized to its content
   * (`height = canvasH * zoom`), but the wrapper has `min-height: 560px`,
   * so a short spec leaves a DEAD ZONE below the SVG that belongs to the
   * wrapper. With the handler on the SVG that band couldn't start a pan
   * (the reported bug: panning worked at the top, over the SVG, but not
   * the bottom, until a tall container was expanded and the SVG grew to
   * cover it). Listening on the wrapper covers both regions.
   *
   * Empty-background detection: fire only when the pointerdown landed on
   * the wrapper's own background (`ev.target === scrollWrapperEl`, the
   * dead zone) OR on the SVG root element itself (`instanceof
   * SVGSVGElement`, the canvas background) — NOT on a child
   * `<rect>` / `<path>` / `<g>`. Children carry their own gestures (leaf
   * scrub, container drag, edge inspect), so this keeps pan disjoint from
   * every existing interaction. The sticky toolbar/panels are ordinary
   * descendants too, so clicks there fall through this guard unharmed.
   *
   * Pointer capture: setPointerCapture on the wrapper (not window) so the
   * gesture survives the cursor leaving the wrapper bounds AND so the
   * window-level pointermove listeners that container/leaf drags rely on
   * can't accidentally pick up these events.
   *
   * Cursor: `cursor: grab` on `.graph-view` is the resting state (the SVG
   * and dead zone inherit it; interactive children override); the
   * `.panning` class on the wrapper toggles to `grabbing` for the
   * duration of the gesture. We don't lean on `:active` because pointer
   * capture decouples from the document focus that drives `:active`.
   *
   * Scope: the gesture is a no-op when neither axis overflows the wrapper
   * viewport — there's nothing to pan. The cursor still reads "grab,"
   * which mildly over-promises, but flipping it conditionally on overflow
   * would require reactive tracking of the wrapper's scrollable extent
   * across density + zoom changes. Not worth it.
   */
  const [isPanning, setIsPanning] = createSignal(false);

  const handleCanvasPanPointerDown = (ev: PointerEvent): void => {
    // Only left button (button === 0). Middle/right have other meanings
    // (browser auto-scroll, context menu); don't hijack them.
    if (ev.button !== 0) return;
    const wrapperEl = scrollWrapperEl;
    if (!wrapperEl) return;

    // Pan-surface guard: pan only when the gesture started on a passive
    // canvas surface, never on a control that owns its own gesture. Three
    // surfaces qualify — (a) the wrapper's own background (the dead zone
    // below a short SVG), (b) the SVG root element itself, and (c) a
    // container BODY rect (`graph-container-rect`).
    //
    // (c) is the fix for "I can't drag inside an expanded DES round to move
    // the view" (2026-06-03): an expanded container's interior is fully
    // covered by its own `graph-container-rect`, which sits above the SVG
    // root in paint order — so a pointerdown there used to hit the rect (not
    // the SVG root) and the pan bailed, leaving no pannable surface inside a
    // populated round. The body rect owns NO click/drag gesture (the header
    // band is a SEPARATE rect on top with its own pointerdown→startNodeDrag;
    // leaves / port handles / chevrons stopPropagation), so treating it as a
    // pan surface can't steal another gesture. Edges are deliberately NOT
    // included: a `graph-edge-hit` path owns a click-to-inspect gesture, and
    // immediate pointer capture below would swallow it. Collapsed-container
    // bodies also carry the class and become pannable — harmless, their
    // bodies have no handler and the header still drags via its own rect.
    const target = ev.target;
    const onPanSurface =
      target === wrapperEl ||
      target instanceof SVGSVGElement ||
      (target instanceof Element && target.classList.contains("graph-container-rect"));
    if (!onPanSurface) return;

    // Clicking empty canvas cancels a pending wire (4d-bis) — same "click
    // away to dismiss" reflex as Esc. Runs before the pan bail so it works
    // even on a fully-visible (non-scrolling) spec.
    if (armed() !== null) disarmPort();

    // Bail early if there's nothing to pan in either axis — clicking
    // empty canvas on a fully-visible spec shouldn't capture the pointer
    // for nothing.
    const overflowsX = wrapperEl.scrollWidth > wrapperEl.clientWidth;
    const overflowsY = wrapperEl.scrollHeight > wrapperEl.clientHeight;
    if (!overflowsX && !overflowsY) return;

    ev.preventDefault();
    // Pointer capture keeps the gesture alive when the cursor leaves the
    // wrapper. Best-effort — jsdom (and very old browsers) may not
    // implement it or may reject a non-active pointerId; the listeners
    // below keep the pan working either way (same stance as startNodeDrag).
    try {
      wrapperEl.setPointerCapture(ev.pointerId);
    } catch {
      // capture is an enhancement, not a requirement
    }
    setIsPanning(true);

    let lastClientX = ev.clientX;
    let lastClientY = ev.clientY;

    const onMove = (mv: PointerEvent): void => {
      const dx = mv.clientX - lastClientX;
      const dy = mv.clientY - lastClientY;
      lastClientX = mv.clientX;
      lastClientY = mv.clientY;
      // Drag pulls the canvas in the direction of the pointer, which
      // means scrollLeft moves OPPOSITE the pointer motion.
      wrapperEl.scrollLeft -= dx;
      wrapperEl.scrollTop -= dy;
    };

    const onUp = (up: PointerEvent): void => {
      wrapperEl.removeEventListener("pointermove", onMove);
      wrapperEl.removeEventListener("pointerup", onUp);
      wrapperEl.removeEventListener("pointercancel", onUp);
      try {
        if (wrapperEl.hasPointerCapture?.(up.pointerId)) {
          wrapperEl.releasePointerCapture(up.pointerId);
        }
      } catch {
        // release is best-effort; mirror the capture guard above
      }
      setIsPanning(false);
    };

    wrapperEl.addEventListener("pointermove", onMove);
    wrapperEl.addEventListener("pointerup", onUp);
    wrapperEl.addEventListener("pointercancel", onUp);
  };

  /** Click handler for `[reset zoom]`. Clears horizontal scroll too. */
  const handleResetZoom = (): void => {
    resetViewZoom(spec().id);
    if (scrollWrapperEl) {
      scrollWrapperEl.scrollLeft = 0;
    }
  };

  /**
   * Bundle → JSX adapter. Used by BOTH the pre-leaf `<For>` (non-feedback
   * bundles) and the post-leaf `<For>` (feedback bundles). Extracted from
   * the inline `<For>` callback so both passes share identical edge
   * rendering — only their position in the SVG document order (and thus
   * their z-stacking against leaves) differs.
   *
   * All `createMemo` calls below run inside the consuming `<For>`
   * callback's reactive scope, so they remain fine-grained and re-track
   * exactly the same dependencies as the pre-extraction inline form.
   */
  const renderBundle = (bundle: EdgeBundle) => {
    const edge = bundle.representativeEdge;
    const bundleCount = bundle.auxKeys.length;
    const isBundled = bundleCount >= 2;
    const fromBox = createMemo(() => layout().boxes.get(edge.from));
    // Slice-2 follow-up: visually terminate replica→iterate-container aux
    // edges at the iterate body's FIRST child, not at the iterate
    // container itself. The edge data model is unchanged (`edge.to` still
    // points at the iterate, so Slice 9's validator and Slice 4's
    // inspector keep reading the right consumer); only the rendered
    // arrowhead anchor shifts. For everything else this returns `edge.to`
    // unchanged.
    const toBox = createMemo(() => {
      const targetId = visualEdgeTargetId(edge, nodesById(), containersById());
      return layout().boxes.get(targetId);
    });
    // edgeKey format:
    //   - singleton bundle (N=1) → existing
    //     `${from}|${to}|${auxKey}|${kind}` so the inspector store
    //     dispatches to the per-edge value lookup (zero regression on
    //     every non-bundled spec).
    //   - multi bundle (N≥2) → `bundle:${from}|${to}|${kind}|${isFeedback?1:0}`
    //     so the inspector store dispatches to the bundle-summary lookup
    //     (Slice C).
    const eKey = isBundled
      ? `bundle:${bundle.from}|${bundle.to}|${bundle.kind}|${bundle.isFeedback ? "1" : "0"}`
      : encodeEdgeKey(edge);
    // Port-spreading follow-up to Slice 7c (2026-05-16): for replica-
    // sourced edges in a multi-source graph, shift the target attach
    // point by one slot per globally-stable source row so a fan-IN of N
    // replicas distributes across N points on the consumer's top edge
    // instead of all converging at the center. PORT_GAP scales with
    // LEAF_W so the spread tracks density (~13 px at normal, ~10 at
    // compact, ~16 at comfortable); clamped to ≥6 so the minimum is
    // still visually distinct at tight densities.
    const targetXOffset = createMemo(() => {
      const portGap = Math.max(6, Math.round(consts().LEAF_W / 10));
      // Cap mirrors EdgePath's `offsetCap = to.w/2 - 4` for the vertical
      // regime so high-fanout consumers (≥ ~10 incoming at default LEAF_W)
      // don't see slot-collision pile-ups when EdgePath clamps individual
      // raw offsets. See `consumerPortOffset`'s `cap` docstring for the
      // SHA-256 motivation. We use the LEAF_W as a proxy for the consumer's
      // width — accurate for leaf chips (the common case) and conservative
      // for wider container chips (cap will be smaller than the real
      // half-width, which only matters when the natural extent already fits
      // anyway, so the scale-down branch never fires there).
      const cap = consts().LEAF_W / 2 - 4;
      return consumerPortOffset(edge, portAssignment(), portGap, cap);
    });
    // Same `consumerPortOffset` math, but on the y-axis for the
    // horizontal regime (sources to the left / right of the consumer).
    // EdgePath consumes this prop only when its regime branch picks
    // horizontal; vertical-regime edges ignore it.
    const targetYOffset = createMemo(() => {
      const portGap = Math.max(4, Math.round(consts().LEAF_H / 4));
      // Horizontal-regime cap matches EdgePath's `yOffsetCap = to.h/2 - 4`.
      // At LEAF_H = 40 (default density), cap = ±16 px; SHA-256
      // `final.assemble` has 8 incoming port-flow edges and a natural
      // ±35 px extent that pre-S2(j) clamped slots 0+1 to -16 and slots
      // 6+7 to +16 (visible pile-up). With this cap the gap scales to
      // 32/7 ≈ 4.6 so all 8 slots stay distinct.
      const cap = consts().LEAF_H / 2 - 4;
      return consumerPortOffset(edge, portAssignment(), portGap, cap);
    });
    // Source-side counterpart to `targetYOffset` (Slice S2(k) of
    // sha-256-density-polish, 2026-05-26 — Case B). Returns the SAME
    // slot offset for this edge so the source attach y mirrors the
    // target attach y: adjacent sibling sources feeding one multi-input
    // consumer (e.g. SHA-256 `sigma1-r17/r19/s10 → sigma1`, all on the
    // same row centerline at distinct columns) now leave their right
    // edges at three distinct y values, matching the three slot y's at
    // sigma1's left edge → three parallel-shifted arrows instead of
    // three lines converging on one y. The cap proxy uses LEAF_H
    // (same as targetYOffset) since EdgePath's actual clamp uses
    // `from.h` per-edge — accurate for leaves (the common case),
    // conservative for taller container sources. Per-edge (NOT
    // per-source): a single source feeding multiple multi-input
    // consumers picks up each consumer's slot offset independently
    // for that consumer's edge — `consumerPortOffset` reads the
    // edge → slot mapping, not the source's identity.
    //
    // **Scope: port-flow edges only.** The diagnostic from the 2026-05-26
    // ship-day smoke against `npm run check` revealed that side-aware
    // bucketing inside `buildConsumerPortAssignment` puts AES-CBC's
    // `cbc-xor → initial.add-round-key` (legacy state edge) in the SAME
    // left-side bucket as `key-expansion → initial.add-round-key` (aux
    // edge from the lifted root-level key-expansion, classified as
    // horizontal-regime "left" entry because key-expansion sits far
    // off to the left). That bucket holds 2 edges → 2 slots → the
    // state edge picked up a ±3.5 px source-y shift that pulled the
    // arrow off cbc-xor's right-edge midline. Pre-S2(k) the slot
    // offset only affected the TARGET attach y (a slight slant from
    // source midline to target slot); applying it ALSO to the source
    // shifted the visible exit point on cbc-xor too. The CBC
    // feedback-overhead test pinned the pre-S2(k) appearance, surfacing
    // the scope creep.
    //
    // Restricting to port-flow edges (`kind: "state"` AND `auxKey ===
    // PORT_FLOW_AUX_KEY`) keeps the fix focused on the SHA-256-shape
    // case the user reported — adjacent-source multi-input combines
    // declared via `portInputs` — and leaves every legacy cipher's
    // state-spine + aux fan-IN appearance byte-identical to pre-S2(k).
    // A future hybrid spec with a multi-input port-flow consumer that
    // ALSO has aux edges entering from the same side would need a
    // wider predicate; document this seam if it arises.
    const sourceYOffset = createMemo(() => {
      const portGap = Math.max(4, Math.round(consts().LEAF_H / 4));
      // Producer-tail spreading (horizontal regime) — the outgoing-edge
      // mirror of `targetYOffset`. When a source fans ≥2 tails out of the
      // same (left/right) edge, distribute them along the source's vertical
      // extent. This TAKES PRECEDENCE over the consumer-mirror below: the
      // two key off mutually exclusive conditions (source fanout ≥2 here vs
      // the fanout-1 adjacent-sibling case S2(k) targets), so for SHA-256's
      // fanout-1 sigma/Sigma sources `producerSpread` is 0 and the
      // consumer-mirror still runs — keeping that shipped behavior
      // byte-identical. The win-when-nonzero rule also fixes the case the
      // consumer-mirror can't: a single source feeding two DIFFERENT
      // multi-input consumers whose slots happen to coincide would mirror
      // both tails onto the same source-y; the source-keyed bucket here
      // spreads them apart instead.
      const fromB = fromBox();
      if (fromB) {
        const cap = fromB.h / 2 - 4;
        const producerSpread = producerPortOffset(edge, producerAssignment(), portGap, cap);
        if (producerSpread !== 0) return producerSpread;
      }
      // Consumer-mirror (Slice S2(k)) — port-flow edges only.
      if (edge.kind !== "state" || edge.auxKey !== PORT_FLOW_AUX_KEY) return 0;
      const cap = consts().LEAF_H / 2 - 4;
      return consumerPortOffset(edge, portAssignment(), portGap, cap);
    });
    // Straight-line + offset-start-point + start-dot (2026-05-16,
    // replacement for the curved-edge prototype): row-k replica edges
    // (k ≥ 1) get a horizontal shift to their SOURCE x so the arrow
    // tail emerges from a non-centred point on the replica's bottom
    // edge. Row 0 stays centred. Zero for non-replicas and single-
    // source graphs.
    const sourceXOffset = createMemo(() => {
      const replicaShift = replicaSourceXOffset(
        edge,
        replicaPlacement(),
        consts().REPLICA_SOURCE_X_STEP,
      );
      const fromB = fromBox();
      // Producer-tail spreading (vertical regime) — the outgoing-edge mirror
      // of `targetXOffset`. Spreads a multi-out source's tails across its
      // bottom/top edge. Additive with `replicaShift` (disjoint: a replica
      // owns exactly one outgoing edge → size-1 producer bucket → 0). Caps to
      // the source's inner half-width (matches EdgePath's own source-x clamp).
      let producerShift = 0;
      if (fromB) {
        const portGap = Math.max(6, Math.round(consts().LEAF_W / 10));
        const cap = fromB.w / 2 - 4;
        producerShift = producerPortOffset(edge, producerAssignment(), portGap, cap);
      }
      return replicaShift + producerShift;
    });
    // Whether this edge originates from a fan-out replica. Gates the
    // straight-line path variant + the start-dot render inside
    // EdgePath.
    const isReplicaEdgeMemo = createMemo(() => isReplicaEdge(edge, replicaPlacement()));
    // Focus-dim v0 (S2(m)): this edge fades to ~0.18 opacity when the
    // user has a non-incident node selected. Inside the bundle row so
    // the memo tracks selectedTarget()/replicaPlacement() changes
    // per-edge — flipping focus on/off restyles only the edges whose
    // dim flag actually changed.
    const dimmedMemo = createMemo(() => {
      if (!focusDimActive()) return false;
      const ids = focusedIncidentIds();
      if (ids === null) return false;
      return !ids.has(edge.from) && !ids.has(edge.to);
    });
    return (
      <Show when={fromBox() && toBox()}>
        <EdgePath
          // biome-ignore lint/style/noNonNullAssertion: <Show> guard above
          from={fromBox()!}
          // biome-ignore lint/style/noNonNullAssertion: <Show> guard above
          to={toBox()!}
          // For singletons, `auxKey` is the one aux key; for bundles
          // it's the first one (used in the tooltip; the bundle
          // inspector exposes the full list).
          auxKey={edge.auxKey}
          kind={edge.kind}
          // Cross-iteration aux feedback (e.g. CBC's
          // cbc-snapshot → cbc-xor): renders dashed so the user can
          // read "this is iteration-N → iteration-N+1, not
          // within-iteration flow" at a glance. Also drives the
          // partitioning above — feedback bundles paint AFTER leaves
          // so they aren't hidden behind nodes they happen to cross.
          isFeedback={bundle.isFeedback}
          edgeKey={eKey}
          // `selectedTarget()` dep ensures Solid re-runs this when the
          // selection changes. For singleton bundles the `eKey` matches
          // `encodeEdgeKey(edge)` so `isEdgeSelected` picks it up; for
          // multi bundles the `eKey` carries the `bundle:` prefix so we
          // dispatch through `isBundleSelected` instead.
          isSelected={
            selectedTarget() !== null && (isBundled ? isBundleSelected(eKey) : isEdgeSelected(eKey))
          }
          targetXOffset={targetXOffset()}
          targetYOffset={targetYOffset()}
          sourceXOffset={sourceXOffset()}
          sourceYOffset={sourceYOffset()}
          isReplicaEdge={isReplicaEdgeMemo()}
          dimmed={dimmedMemo()}
          bundleCount={bundleCount}
          // First few aux keys for the tooltip; the bundle inspector
          // (Slice C) shows the full list.
          bundleAuxKeysSample={bundle.auxKeys}
          // Source-color coding (2026-05-19): inline stroke override
          // when this edge's canonical source has an assigned color
          // (master toggle ON + fanout ≥ 2 OR manual override).
          // Endpoint-pill-sourced edges and single-fanout sources fall
          // through (returns undefined → EdgePath uses kind classes).
          //
          // Inlined here (rather than reusing `colorForEdge` from the
          // core helper) so we can leverage the existing `nodesById`
          // memo for the canonical-source lookup — saves an O(N) scan
          // over `graph.nodes` per rendered edge on every graph change.
          sourceColor={(() => {
            const colors = effectiveSourceColors();
            if (colors.size === 0) return undefined;
            if (isEndpointId(edge.from)) return undefined;
            const node = nodesById().get(edge.from);
            const canonical = node?.replicaOf ?? edge.from;
            return colors.get(canonical);
          })()}
          // Source-STROKE coding (A3a). Same canonical-source resolution as
          // `sourceColor` (reuse the `nodesById` memo, no per-edge O(N)
          // scan), then expand the assigned style NAME into its four-channel
          // bundle. Returns `undefined` for edges that should stay un-styled:
          // toggle OFF (empty map), endpoint-pill sources, sources absent
          // from the map, AND — critically — the `solid` baseline (all four
          // channels at their defaults). Falling through on `solid` keeps
          // solid-assigned sources byte-identical to today's un-styled edge,
          // the invariant that makes this chunk non-disruptive.
          sourceStroke={(() => {
            const strokes = effectiveSourceStrokes();
            if (strokes.size === 0) return undefined;
            if (isEndpointId(edge.from)) return undefined;
            const node = nodesById().get(edge.from);
            const canonical = node?.replicaOf ?? edge.from;
            const name = strokes.get(canonical);
            if (name === undefined) return undefined;
            const style = strokeStyleByName(name);
            // Solid baseline → no visual change; fall through un-styled.
            if (
              style.dasharray === null &&
              style.widthMul === 1 &&
              style.dashoffset === undefined
            ) {
              return undefined;
            }
            return style;
          })()}
        />
      </Show>
    );
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
          // Drag-to-pan grabbing cursor while a pan gesture is active.
          // The gesture is owned by this wrapper (not the SVG) so the
          // dead zone below a short SVG is pannable too — see
          // `handleCanvasPanPointerDown`.
          panning: isPanning(),
          "graph-drop-zone-active": dragOverActive(),
          // Activated by the module-level signal in StepPalette during a
          // palette drag. CSS rules in app.css read the data-state-shape
          // attribute on each drop anchor and dim those whose shape
          // doesn't match the dragged step's input contract.
          "dragging-bytes": draggedInputShape() === "bytes",
          "dragging-matrix": draggedInputShape() === "matrix4x4-bytes",
        }}
        onPointerDown={handleCanvasPanPointerDown}
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
            {/* Replication threshold — lives right next to its OWN checkbox
                (2026-05-30 reorg). Previously it rendered after the "color by
                source" checkbox, so it read as a coloring control when it
                actually governs replica splitting. The `>` glyph + strict
                "more than" semantics are unchanged. */}
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
            {/* Source-color coding master toggle (2026-05-19). Defaults ON
                — every source's edges paint a deterministic
                colour so the eye can track source identity at a glance.
                Toggling OFF reverts every edge to today's kind-based
                styling (light-blue aux / white state). The per-source
                colour panel (rendered below the replication panel) is
                visible whenever this toggle is ON and the graph has at
                least one colorable source. */}
            <label
              class="graph-replicate-toggle"
              title="Paint each source's outgoing edges in a distinct colour"
            >
              <input
                type="checkbox"
                checked={sourceColoringEnabled()}
                onChange={toggleSourceColoringEnabled}
                data-testid="source-coloring-toggle"
              />
              color by source
            </label>
            {/* Coloring fanout threshold (2026-05-30; per-spec 2026-07-10;
                universalised 2026-07-11) — the "color by source" knob, right
                after its own checkbox. A source auto-colours when its fanout is
                ≥ this value. Min 0 (colour every source), max 99; the DEFAULT is
                now ${DEFAULT_COLOR_THRESHOLD} for EVERY spec (colour every
                source on first open). `≥` glyph matches the inclusive semantics
                (vs the replication threshold's strict `>`). Disabled when the
                master coloring toggle is OFF so the knob's no-op state is
                visible at a glance. */}
            <label
              class="graph-replicate-threshold"
              title={`Sources fanning out to at least this many consumers get an auto colour (default ${DEFAULT_COLOR_THRESHOLD} for every spec — colours every edge). Raise it to colour only the biggest fan-outs.`}
            >
              <span class="graph-replicate-threshold-label">&ge;</span>
              <input
                type="number"
                class="graph-color-threshold-input"
                min={COLOR_THRESHOLD_MIN}
                max={COLOR_THRESHOLD_MAX}
                step={1}
                value={colorThreshold()}
                disabled={!sourceColoringEnabled()}
                onInput={(e) => {
                  const parsed = Number.parseInt(e.currentTarget.value, 10);
                  setColorThreshold(spec().id, parsed);
                }}
                aria-label="Fanout threshold for source coloring"
                data-testid="color-threshold-input"
              />
            </label>
            {/* Source-STROKE styling master toggle (A3b, 2026-07-09). The
                second, orthogonal disambiguation channel: each source's edges
                get a distinct DASH pattern (× line-cap × weight × phase) so
                sources stay tellable-apart even when their colours collide —
                which they do on dense specs (more sources than the 8-colour
                palette). PER-SPEC, and as of 2026-07-11 ships ON for EVERY spec
                (previously OFF-except-SHA-256/RSA; see `view-source-strokes.ts`);
                the same per-source panel below hosts the dash dropdown next to
                the colour swatch. Owns its OWN fanout threshold (the next
                control), independent of the colour threshold since 2026-07-10. */}
            <label
              class="graph-replicate-toggle"
              title="Give each source's outgoing edges a distinct dash pattern (a second channel alongside colour)"
            >
              <input
                type="checkbox"
                checked={strokeStylingEnabled()}
                onChange={() => toggleSourceStrokeStylingEnabled(spec().id)}
                data-testid="source-stroke-styling-toggle"
              />
              style by source
            </label>
            {/* Styling fanout threshold (2026-07-10; universalised 2026-07-11)
                — the "style by source" knob, INDEPENDENT of the colour
                threshold above. A source auto-styles when its fanout is ≥ this
                value. Same range/glyph as the colour knob; DEFAULT now
                ${DEFAULT_STROKE_THRESHOLD} for EVERY spec. Disabled when the
                master styling toggle is OFF. */}
            <label
              class="graph-replicate-threshold"
              title={`Sources fanning out to at least this many consumers get an auto dash style (default ${DEFAULT_STROKE_THRESHOLD} for every spec). Independent of the colour threshold.`}
            >
              <span class="graph-replicate-threshold-label">&ge;</span>
              <input
                type="number"
                class="graph-stroke-threshold-input"
                min={STROKE_THRESHOLD_MIN}
                max={STROKE_THRESHOLD_MAX}
                step={1}
                value={strokeThreshold()}
                disabled={!strokeStylingEnabled()}
                onInput={(e) => {
                  const parsed = Number.parseInt(e.currentTarget.value, 10);
                  setStrokeThreshold(spec().id, parsed);
                }}
                aria-label="Fanout threshold for source styling"
                data-testid="stroke-threshold-input"
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
            {/* Bulk collapse / expand of every container in the spec. A
                shortcut over clicking each round-group chevron one at a time —
                the forcing case is a many-round cipher (AES-256, DES, SHA-256)
                where the user wants the whole canvas folded to rounds, or
                fully unfolded to inspect every leaf. Both route through the
                same effective-collapsed algebra as the per-container chevron
                (`collapseAllContainers` / `expandAllContainers` in
                `stores/layout.ts`), so they compose cleanly with the spec's
                `defaultCollapsed` declarations and are undoable with Ctrl+Z.
                Each is disabled when it would be a no-op. */}
            <button
              type="button"
              class="graph-view-toolbar-button graph-view-layout-reset"
              data-testid="graph-view-collapse-all"
              onClick={() => {
                cancelLayoutGesture();
                collapseAllContainers(spec().id, allContainerIds(), defaultCollapsedSet());
              }}
              disabled={!hasExpandedContainer()}
              title="Collapse every container (rounds, groups) on the canvas"
            >
              collapse all
            </button>
            <button
              type="button"
              class="graph-view-toolbar-button graph-view-layout-reset"
              data-testid="graph-view-expand-all"
              onClick={() => {
                cancelLayoutGesture();
                expandAllContainers(spec().id, allContainerIds(), defaultCollapsedSet());
              }}
              disabled={!hasCollapsedContainer()}
              title="Expand every container (rounds, groups) on the canvas"
            >
              expand all
            </button>
            {/* Hard-reset of the per-spec layout sidecar (draggable-
                replicas plan Slice 5, 2026-05-19). Clears positions,
                relativePositions, collapsedGroups, and replicationModes
                in one click — same envelope `setLayoutForSpec(specId,
                null)` writes when a Load brings in a layout-less
                document. Confirm prompt is the cheap safety net; the
                button is disabled when there's nothing to reset so the
                user can't accidentally trigger the prompt on an
                already-clean spec.

                Part B split (graph-legibility plan): a built-in WITH a
                curated default layout offers TWO resets — "to default"
                (discard user pins, fall back to the curated arrangement)
                and "to automatic" (discard user pins AND suppress the
                curated default for this session, showing raw auto-layout).
                A built-in WITHOUT a curated default keeps the single
                "reset layout" (identical to today). The catalogue is empty
                in B1, so every shipped spec renders the single button until
                later chunks author layouts. */}
            <Show
              when={hasCuratedDefault()}
              fallback={
                <button
                  type="button"
                  class="graph-view-toolbar-button graph-view-layout-reset"
                  data-testid="graph-view-layout-reset"
                  onClick={() => {
                    if (
                      window.confirm(
                        "Reset graph layout?\n\nThis clears every pin, collapse, and replication override for this spec. You can undo it with Ctrl+Z.",
                      )
                    ) {
                      cancelLayoutGesture();
                      setLayoutForSpec(spec().id, null);
                    }
                  }}
                  disabled={!hasUserLayout(userLayout())}
                  title="Clear every pin, collapse, and replication override for this spec"
                >
                  reset layout
                </button>
              }
            >
              <button
                type="button"
                class="graph-view-toolbar-button graph-view-layout-reset"
                data-testid="graph-view-layout-reset-default"
                onClick={() => {
                  if (
                    window.confirm(
                      "Reset to the curated default layout?\n\nThis discards your pins, collapses, and overrides for this spec and restores the built-in arrangement. You can undo it with Ctrl+Z.",
                    )
                  ) {
                    cancelLayoutGesture();
                    setLayoutForSpec(spec().id, null);
                    unsuppressCuratedLayout(spec().id);
                  }
                }}
                disabled={!hasUserLayout(userLayout()) && !isCuratedLayoutSuppressed(spec().id)}
                title="Discard your changes and restore the built-in curated layout"
              >
                reset to default
              </button>
              <button
                type="button"
                class="graph-view-toolbar-button graph-view-layout-reset"
                data-testid="graph-view-layout-reset-automatic"
                onClick={() => {
                  if (
                    window.confirm(
                      "Reset to automatic layout?\n\nThis discards your pins and ignores the curated default, showing the raw auto-layout for this session. You can undo it with Ctrl+Z.",
                    )
                  ) {
                    cancelLayoutGesture();
                    setLayoutForSpec(spec().id, null);
                    suppressCuratedLayout(spec().id);
                  }
                }}
                disabled={!hasUserLayout(userLayout()) && isCuratedLayoutSuppressed(spec().id)}
                title="Discard your changes and the curated default, showing raw auto-layout (resets on reload)"
              >
                reset to automatic
              </button>
            </Show>
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
                              onClick={() => {
                                cancelLayoutGesture();
                                setReplicationMode(spec().id, src.id, null);
                              }}
                              title="Defer to the global threshold"
                            >
                              auto
                            </button>
                            <button
                              type="button"
                              classList={{ active: currentMode() === "always" }}
                              onClick={() => {
                                cancelLayoutGesture();
                                setReplicationMode(spec().id, src.id, "always");
                              }}
                              title="Always replicate this source"
                            >
                              always
                            </button>
                            <button
                              type="button"
                              classList={{ active: currentMode() === "never" }}
                              onClick={() => {
                                cancelLayoutGesture();
                                setReplicationMode(spec().id, src.id, "never");
                              }}
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
          {/* Source-styling panel (2026-05-19; A3b added the stroke channel
              2026-07-09). Shown when EITHER master toggle (colour OR stroke)
              is ON and at least one source exists — gating on colour alone
              would hide the dash dropdown from a strokes-only spec (e.g.
              SHA-256 with colours toggled off). Mirrors the replication-
              overrides panel's header / chevron / open-state shape so the two
              graph-level panels read as siblings. One row per source: a
              clickable colour swatch (native <input type="color">, disabled
              when colouring is off), a dash-style dropdown (disabled when
              styling is off), the source's canonical id, the fanout count,
              and a per-row colour-[reset] button when a manual colour is
              active. Footer has [clear all manual] and [autocolor now]. */}
          <Show
            when={
              (sourceColoringEnabled() || strokeStylingEnabled()) && sourceColorRows().length > 0
            }
          >
            <div class="graph-source-colors-panel">
              <button
                type="button"
                class="graph-replication-panel-header"
                data-testid="source-colors-panel-toggle"
                data-open={colorsPanelOpen() ? "true" : "false"}
                aria-expanded={colorsPanelOpen() ? "true" : "false"}
                onClick={() => toggleColorsPanelOpen(spec().id)}
                title={colorsPanelOpen() ? "Collapse source styling" : "Expand source styling"}
              >
                <span class="graph-replication-panel-chevron" aria-hidden="true">
                  ▸
                </span>
                source styling
                <span class="graph-replication-panel-hint">
                  {sourceColorRows().length} source
                  {sourceColorRows().length === 1 ? "" : "s"}
                </span>
              </button>
              <Show when={colorsPanelOpen()}>
                <div class="graph-replication-panel-body">
                  {/* Sub-toggle: expand the listing to include
                      single-output sources. Default OFF so the panel
                      doesn't crowd on ciphers with many distinct
                      sources; flipping ON adds a row per single-output
                      source with a hatched swatch ("click to assign").
                      Single-output sources never auto-colour — they
                      paint only when the user picks a colour. */}
                  <label
                    class="graph-source-colors-subtoggle"
                    title="Show single-output sources in the list (start uncoloured, click swatch to assign)"
                  >
                    <input
                      type="checkbox"
                      checked={includeSingleSources()}
                      onChange={toggleIncludeSingleSources}
                      data-testid="source-colors-include-single-toggle"
                    />
                    include single-output sources
                  </label>
                  <For each={sourceColorRows()}>
                    {(row) => (
                      <div
                        class="graph-source-colors-row"
                        data-testid={`source-colors-row-${row.id}`}
                      >
                        {/* Native color picker via type=color; the
                            swatch IS the input (CSS hides the default
                            chrome). Clicking opens the OS-native picker
                            on every browser we support. Persists per-
                            spec via the override store.

                            For uncoloured rows (single-fanout sources
                            without a manual override) we tag the
                            swatch with `-unset` so CSS paints a
                            hatched pattern indicating "no colour yet,
                            click to pick." The input's `value`
                            attribute defaults to `#000000` for the
                            picker's initial selection; user click
                            picks any colour → `onInput` fires →
                            override persists → row recomputes with
                            real colour. */}
                        <input
                          type="color"
                          class="graph-source-colors-swatch"
                          classList={{
                            "graph-source-colors-swatch-unset": row.color === undefined,
                          }}
                          value={row.color ?? "#888888"}
                          disabled={!sourceColoringEnabled()}
                          aria-label={`Color for source ${row.id}`}
                          onInput={(e) =>
                            setSourceColorOverride(spec().id, row.id, e.currentTarget.value)
                          }
                          data-testid={`source-colors-swatch-${row.id}`}
                        />
                        {/* Dash-style dropdown (A3b). The persisted value is a
                            style NAME string; the empty option maps to "auto"
                            (clears the manual override → `setSourceStroke(…,
                            null)`), and its label shows what auto currently
                            assigns so the user can see the default without
                            committing to it. A manual pick writes the chosen
                            name. Disabled when the stroke channel is off for
                            this spec, so the control still ADVERTISES the
                            channel exists (greyed, not hidden). */}
                        <select
                          class="graph-source-strokes-select"
                          disabled={!strokeStylingEnabled()}
                          value={row.isStrokeManual ? (row.strokeName ?? "") : ""}
                          aria-label={`Dash style for source ${row.id}`}
                          onChange={(e) => {
                            const name = e.currentTarget.value;
                            setSourceStroke(spec().id, row.id, name === "" ? null : name);
                          }}
                          data-testid={`source-strokes-select-${row.id}`}
                        >
                          <option value="">auto ({row.autoStrokeName ?? "solid"})</option>
                          <For each={STROKE_STYLE_CATALOGUE}>
                            {(style) => <option value={style.name}>{style.name}</option>}
                          </For>
                        </select>
                        <span class="graph-replication-row-id" title={row.id}>
                          {row.id}
                        </span>
                        <span class="graph-replication-row-fanout">
                          {row.fanout} {row.fanout === 1 ? "edge" : "edges"}
                        </span>
                        <Show when={row.isManual}>
                          <button
                            type="button"
                            class="graph-source-colors-reset"
                            onClick={() => clearSourceColorOverride(spec().id, row.id)}
                            title={
                              row.isAutoColored
                                ? "Revert this source to its auto-assigned color"
                                : "Remove this manual color (source returns to uncoloured)"
                            }
                          >
                            reset
                          </button>
                        </Show>
                      </div>
                    )}
                  </For>
                  <div class="graph-source-colors-footer">
                    <button
                      type="button"
                      class="graph-source-colors-footer-button"
                      onClick={() => clearAllSourceColorOverrides(spec().id)}
                      title="Remove every manual override for this spec"
                      data-testid="source-colors-clear-all"
                    >
                      clear all manual
                    </button>
                    <button
                      type="button"
                      class="graph-source-colors-footer-button"
                      onClick={() => clearAllSourceColorOverrides(spec().id)}
                      title="Recompute the auto-assigned palette for this spec"
                      data-testid="source-colors-autocolor"
                    >
                      autocolor now
                    </button>
                  </div>
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
                bundles={() => bundledGraph().bundles}
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
            {/* Sort by depth so outer containers (shallower path) paint
                FIRST and inner containers paint ON TOP. Without this,
                an outer group's rect (rendered last because it came
                later in `graph().containers`'s natural order) covered
                its children's perimeter strips — visible as "no
                round-N border around individual DES rounds" in the
                2026-05-20 Phase 6e smoke. SVG paint order is document
                order, so emitting parents first puts their <rect>
                under the children's <rect>. */}
            <For each={containersInPaintOrder()}>
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
                        // `inDefaults` routes the flip to expandedGroups vs
                        // collapsedGroups so the "never in both sets" invariant
                        // holds — see `toggleCollapse` in `stores/layout.ts`.
                        onToggleCollapse={() => {
                          // Clear any stuck drag gesture first so this discrete
                          // edit can't be coalesced away (C4, cancelLayoutGesture).
                          cancelLayoutGesture();
                          toggleCollapse(
                            spec().id,
                            container.id,
                            defaultCollapsedSet().has(container.id),
                          );
                        }}
                        warnings={containerWarnings()}
                        stateShape={shapesByAnchor().get(container.id) ?? ""}
                        // Live preview during a palette drag: highlights this
                        // container whenever the cursor's resolved anchor
                        // (`closest("[data-drop-anchor]")`) is THIS container.
                        isDropTargetActive={dragOverAnchorId() === container.id}
                        // Per-container ↺ reset affordance (draggable-replicas
                        // plan Slice 4 follow-up, 2026-05-19). Inlined as a
                        // reactive prop expression — `pinnedMap()` is read on
                        // every re-evaluation, so the glyph appears the moment
                        // the user's drag writes a pin and disappears when the
                        // pin is cleared. (A `const x = pinnedMap().has(...)`
                        // captured at row-init time wouldn't be reactive — see
                        // CLAUDE.md's "For callbacks aren't reactive scopes".)
                        onResetAbsolutePin={
                          pinnedMap().has(container.id)
                            ? () => clearNodePosition(spec().id, container.id)
                            : undefined
                        }
                      />
                    )}
                  </Show>
                );
              }}
            </For>

            {/* Canonical-Feistel decorations: F-function box + L/R rail labels
              per expanded Feistel round (DES today). Drawn after containers and
              before edges/leaves so the F-box reads as a subtle background
              grouping the F-stack column; `pointer-events:none` so it never
              eats clicks. The labels name `split`'s two output halves. */}
            <For each={feistelDecorations()}>
              {(d) => (
                <g class="graph-feistel-decor" pointer-events="none">
                  <rect
                    class="graph-feistel-fbox"
                    x={d.fBox.x}
                    y={d.fBox.y}
                    width={d.fBox.w}
                    height={d.fBox.h}
                    rx="8"
                  />
                  <text class="graph-feistel-fbox-label" x={d.fBox.x + 8} y={d.fBox.y + 16}>
                    F
                  </text>
                  <text class="graph-feistel-rail-label" x={d.lLabel.x} y={d.lLabel.y}>
                    L
                  </text>
                  <text
                    class="graph-feistel-rail-label"
                    x={d.rLabel.x}
                    y={d.rLabel.y}
                    text-anchor="end"
                  >
                    R
                  </text>
                </g>
              )}
            </For>

            {/* Canonical-Twofish decorations: a dashed "g" box around EACH of
              the two g-function stacks. Reuses the Feistel F-box styling. */}
            <For each={twofishDecorations()}>
              {(d) => (
                <g class="graph-feistel-decor" pointer-events="none">
                  <For each={[d.g0Box, d.g1Box]}>
                    {(gb) => (
                      <>
                        <rect
                          class="graph-feistel-fbox"
                          x={gb.x}
                          y={gb.y}
                          width={gb.w}
                          height={gb.h}
                          rx="8"
                        />
                        <text class="graph-feistel-fbox-label" x={gb.x + 8} y={gb.y + 16}>
                          g
                        </text>
                      </>
                    )}
                  </For>
                </g>
              )}
            </For>

            {/* Edges between leaf/container centers. Drawn before leaves so the
              lines tuck under the rectangle fills.

              Bundling pass (2026-05-17): we iterate `bundledGraph().bundles`
              rather than `graph().edges`. Singleton bundles (the vast
              majority — every state edge and every aux pair with only
              one auxKey) render IDENTICALLY to the pre-bundle world; only
              multi-auxKey bundles (post-replication, post-collapse cases
              like AES-128 ECB key-expansion → collapsed iterate) collapse
              into a single thicker arrow with a `×N` label.

              Two-pass partition (2026-05-18): this `<For>` renders the
              non-feedback bundles only — the feedback partition is
              rendered AFTER the leaves below so cross-iteration arrows
              (CBC's `cbc-snapshot → cbc-xor`) sit on top of any nodes
              they happen to cross. See `nonFeedbackBundles` /
              `feedbackBundles` memos for the rationale. */}
            <For each={visibleNonFeedbackBundles()}>{renderBundle}</For>

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
                          // returns the "endpoint" status carrying the actual
                          // I/O value (frames[0].stateBefore for input,
                          // trace.finalState for output) — the value-row
                          // formats it just like any state row.
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
                // Wider sibling of `isInsideIterate` (Slice S2(j), 2026-05-26):
                // includes EVERY iteration-style container — `iterate`,
                // `for-each-subgraph`, `for-each-subgraph-with-history`.
                // Drives the gate for iterate-body draggability so leaves
                // inside SHA-256's `msg-schedule` (a `for-each-subgraph-
                // with-history`) become draggable too. Non-looping `group`
                // containers (`round.N`, AES round bodies) are handled by
                // the separate `isInsideGroup` predicate below — they were
                // added to the draggable gate in Finding 4 (2026-05-30).
                const isInsideIteration = node.containerPath.some((id) => {
                  const c = containersById().get(id);
                  const k = c?.kind;
                  return (
                    k === "iterate" ||
                    k === "for-each-subgraph" ||
                    k === "for-each-subgraph-with-history"
                  );
                });
                // Non-looping `group` sibling of `isInsideIteration`
                // (Finding 4, 2026-05-30). AES round bodies (`round.N`) are
                // `group` containers, so their leaves (sub-bytes / shift-rows /
                // mix-columns / add-round-key) were excluded from the draggable
                // gate below — the user asked to make them movable, same as the
                // iteration-body leaves enabled in S2(j). The layout passes
                // already apply `relativePins.get(childId)` deltas to GROUP
                // children too (same code path as iterate children, cf. lines
                // ~1299, ~1452, ~1746), so enabling drag here is a pure gate
                // flip + relative-pin mode — no layout change. The only
                // behavioral shift is the click path: a draggable leaf drops
                // its `<g onClick>` and instead synthesizes the click on
                // sub-threshold pointer release via the drag handler's
                // `onClickFallback` (see LeafRect ~6360). Real-browser scrub /
                // select behavior is preserved (the fallback runs the same
                // `handleLeafClick` + `toggleSelectedNode`); jsdom `fireEvent.
                // click` does NOT traverse that path, so the group-child click
                // tests were audited + re-pointed at the pointer-event path.
                const isInsideGroup = node.containerPath.some((id) => {
                  const c = containersById().get(id);
                  return c?.kind === "group";
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
                // Conditional spread for the drag handler.
                //
                //   - Root-level non-replica leaves (e.g. AES's
                //     `key-expansion`, `initial.add-round-key`) get the
                //     legacy ABSOLUTE-pin drag — clamped to (0,0) so they
                //     can't be dragged off the canvas.
                //   - Replicas (`replicaOf` set) and block chips
                //     (`blockChipOf` set) get the RELATIVE-pin drag
                //     (draggable-replicas plan, Slice 3 — 2026-05-19): pin
                //     a delta from the auto position, so the chip rides
                //     its anchor (consumer for replicas, iterate for
                //     chips) when that anchor moves. NOT clamped — auto
                //     position is already deep in the canvas, and moving
                //     toward the upper-left is a valid gesture.
                //   - Leaves inside iteration-style containers (iterate /
                //     for-each-subgraph / for-each-subgraph-with-history)
                //     also get the RELATIVE-pin drag (Slice S2(j),
                //     2026-05-26). The user reported visual pile-ups
                //     inside expanded SHA-256 `msg-schedule` (a
                //     `for-each-subgraph-with-history`) where converging
                //     arrows make it impossible to follow which edge feeds
                //     which leaf; making the leaves draggable gives the
                //     user a manual untangle. The layout passes already
                //     apply `relativePins.get(childId)` deltas to
                //     iterate/group children (cf. lines ~1299, ~1452,
                //     ~1746), so no layout change is needed — the gate
                //     flip alone enables persistence + reset glyph.
                //   - Leaves inside non-looping `group` containers (AES
                //     `round.N` bodies) ALSO get the relative-pin drag
                //     since Finding 4 (2026-05-30). Previously excluded so
                //     their leaves kept the legacy `<g onClick>` wiring;
                //     the user asked to make round-body leaves movable, so
                //     `isInsideGroup` now joins the gate and the click
                //     tests were re-pointed at the pointer-event path.
                const dragMode =
                  isReplicaLike || isInsideIteration || isInsideGroup
                    ? ("relative" as const)
                    : ("absolute" as const);
                const isDraggable =
                  isReplicaLike || isRootLevel || isInsideIteration || isInsideGroup;
                const dragProps = isDraggable
                  ? {
                      onPointerDown: (e: PointerEvent) =>
                        startNodeDrag(
                          node.stepId,
                          e,
                          () => {
                            // Click fallback (sub-threshold drag release) on
                            // a draggable leaf — keep both behaviors aligned
                            // with the non-draggable onClick path below:
                            // scrub the trace AND toggle inspector selection.
                            handleLeafClick(clickTargetId);
                            toggleSelectedNode(inspectorTargetId);
                          },
                          { mode: dragMode },
                        ),
                    }
                  : {};
                const leafWarnings = createMemo(() => warningsByVisibleId().get(node.stepId) ?? []);
                // ─── Port-wiring per-leaf state (4d-bis, Slice E) ──────────
                // Only REAL spec leaves (not replicas / block chips) join the
                // wiring gesture. Input ports come from the leaf's registration
                // so dynamic-arity primitives (xor `operandN`) enumerate right.
                const wiringInputPorts = createMemo<string[]>(() => {
                  if (isReplicaLike || isBlockChip) return [];
                  const leaf = findStep(spec(), node.stepId);
                  if (leaf === null) return [];
                  const reg = registry.getRegistration(leaf.type);
                  if (reg === undefined) return [];
                  return [...resolvePortMap(reg.shape.inputs, leaf.params).keys()];
                });
                // Which input port of THIS leaf is currently armed (else null).
                const armedPortHere = createMemo<string | null>(() => {
                  const a = armed();
                  return a !== null && a.stepId === node.stepId ? a.portName : null;
                });
                // When a wire is armed on ANOTHER leaf and THIS leaf is a legal
                // source, the coerce verdict for binding it (null = not a target).
                const wireTargetRole = createMemo<"ok" | "coerce" | null>(() => {
                  const a = armed();
                  if (a === null || a.stepId === node.stepId || isReplicaLike || isBlockChip) {
                    return null;
                  }
                  const src = armedLegalByNode()?.get(node.stepId);
                  return src ? src.compat : null;
                });
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
                        // `draggable` controls the LeafRect's class + click-
                        // vs-drag dispatch internally. Replicas + chips are
                        // now draggable too (relative-pin mode) — see the
                        // `dragProps` gate above for the per-mode split.
                        draggable={isDraggable}
                        isReplica={isReplicaLike}
                        dropAnchorId={clickTargetId}
                        // Reactive: the JSX expression re-evaluates when
                        // dragOverAnchorId() changes, and Solid forwards
                        // the new prop value through to LeafRect — which
                        // toggles `.graph-drop-target-active` accordingly.
                        isDropTargetActive={dragOverAnchorId() === clickTargetId}
                        {...blockSpanProps}
                        {...dragProps}
                        // Per-node reset affordance for the relative-pin
                        // delta: inline reactive expression so the glyph
                        // appears the moment the user's drag writes a pin
                        // and disappears when the pin is cleared. Mirrors
                        // the ContainerRect onResetAbsolutePin pattern —
                        // `<For>` row callbacks aren't reactive scopes per
                        // CLAUDE.md, so a `const x = ...has(id) ? ... : ...`
                        // captured at row-init time wouldn't reactively
                        // update when relativePinsMap() changed.
                        onResetRelativePin={
                          // Reset glyph appears whenever the node has a
                          // RELATIVE pin — replicas/chips since Slice 3,
                          // iteration-body leaves since S2(j), and group
                          // (AES round body) leaves since Finding 4.
                          // Root-level leaves use absolute pins (or no pin
                          // at all), so they're excluded.
                          (isReplicaLike || isInsideIteration || isInsideGroup) &&
                          relativePinsMap().has(node.stepId)
                            ? () => clearRelativePosition(spec().id, node.stepId)
                            : undefined
                        }
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
                        // ─── Port-wiring (4d-bis, Slice E) ──────────────────
                        inputPorts={wiringInputPorts()}
                        // Per-port arrival points so each input dot sits where
                        // its incoming arrow actually lands (2026-07-12); absent
                        // ports fall back to the left-edge placement in LeafRect.
                        inputPortPoints={portArrivalPoints().get(node.stepId)}
                        armedPortName={armedPortHere()}
                        wireTarget={wireTargetRole()}
                        onArmPort={(portName) => toggleArmPort(node.stepId, portName)}
                        onBindHere={() => {
                          const a = armed();
                          const src = armedLegalByNode()?.get(node.stepId);
                          if (a !== null && src !== undefined) {
                            bindPortInSpec(a.stepId, a.portName, {
                              node: src.node,
                              port: src.port,
                            });
                            disarmPort();
                          }
                        }}
                      />
                    )}
                  </Show>
                );
              }}
            </For>

            {/* Feedback-edge pass (2026-05-18). Cross-iteration aux
              arrows — today only CBC's `cbc-snapshot → cbc-xor`,
              future OFB/CFB the same shape — paint here, AFTER the
              leaves, so a feedback arc that crosses an unrelated node
              (in CBC, `round.0.add-round-key`) doesn't disappear
              behind the box fill. Shares `renderBundle` with the
              first pass so the EdgePath / tooltip / selection-halo
              behavior is identical; only the SVG document-order
              position (and thus z-stacking against leaves) differs.

              Tradeoff: the arrowhead tip now lands ON TOP of the
              consumer leaf instead of tucking under. With dashed
              stroke at 0.55 opacity the line reads as overlapping the
              box rather than "stuck to" the front face — see
              `.graph-edge-feedback` in `app.css`. */}
            <For each={feedbackBundles()}>{renderBundle}</For>

            {/* Inter-round Feistel SWAP (the "X"). Drawn AFTER the leaves so
              the crossing reads on top of the empty inter-round band. Two
              cubic half-wires per round boundary, crossing when the source
              round swaps (DES rounds 1..15) — the textbook depiction that R
              becomes the next round's left half and (L⊕F) its right. The
              straight `recombine → split` carry was suppressed from the edge
              render (`visibleNonFeedbackBundles`). A `<title>` notes that the
              port-native cipher realizes the swap via the concat order. */}
            <For each={feistelSwaps()}>
              {(s) => {
                type Wire = { x1: number; y1: number; x2: number; y2: number };
                // Cubic with vertical control points → a smooth crossing.
                const path = (w: Wire) =>
                  `M ${w.x1} ${w.y1} C ${w.x1} ${(w.y1 + w.y2) / 2} ${w.x2} ${(w.y1 + w.y2) / 2} ${w.x2} ${w.y2}`;
                // Label each wire by the VALUE it carries, so a student can
                // trace R → new_L despite the concat byte order. Placed ~70%
                // toward the target (not the midpoint) so the two labels sit on
                // the separated ends rather than overlapping at the crossing.
                const labelAt = (w: Wire) => ({
                  x: w.x1 + 0.7 * (w.x2 - w.x1),
                  y: w.y1 + 0.7 * (w.y2 - w.y1),
                });
                const carryMid = labelAt(s.carry);
                const mixedMid = labelAt(s.mixed);
                // Render one swap rail: the visible tinted wire (+ arrowhead),
                // then a wide transparent hit path so the thin 2px wire is
                // comfortably clickable → the value inspector. Mirrors EdgePath's
                // two-layer idiom (visible path `pointer-events:none`; hit path
                // `pointer-events:stroke` on a 12px transparent stroke). Each rail
                // keys the internal round edge that carries its half, so clicking
                // `R` inspects R's bytes and `L⊕F` inspects the fxor output.
                const rail = (w: Wire, color: string, edgeKey: string, label: string) => {
                  const d = path(w);
                  const toggle = () => toggleSelectedEdge(edgeKey);
                  return (
                    <>
                      {/* Concrete inline `stroke` (not `currentColor`) so the
                          `context-stroke` arrowhead marker resolves to this rail's
                          hue — a `currentColor` stroke leaves the arrowhead the
                          default paint (user-flagged 2026-07-13). `color` stays set
                          so the selected-halo `drop-shadow(... currentColor)` tints. */}
                      <path
                        class="graph-feistel-swap-wire"
                        classList={{
                          "graph-feistel-swap-wire-selected": isEdgeSelected(edgeKey),
                        }}
                        d={d}
                        marker-end="url(#graph-arrow-state)"
                        style={{ color, stroke: color }}
                        pointer-events="none"
                      />
                      {/* Wide transparent hit companion — same idiom as
                          `.graph-edge-hit` (onClick + onKeyDown + data-edge-key,
                          no ARIA role: an SVG path is a non-interactive element,
                          so biome rejects `role="button"`; the EdgePath hit path
                          it mirrors carries none either). */}
                      <path
                        class="graph-feistel-swap-hit"
                        d={d}
                        data-edge-key={edgeKey}
                        onClick={(e) => {
                          // stopPropagation so the click doesn't bubble to the
                          // canvas (empty-area drag-cancel handlers).
                          e.stopPropagation();
                          toggle();
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            toggle();
                          }
                        }}
                      >
                        <title>{`${label} — click to inspect this half's bytes`}</title>
                      </path>
                    </>
                  );
                };
                return (
                  <g
                    class="graph-feistel-swap"
                    classList={{ "graph-feistel-swap-crossed": s.swap }}
                  >
                    <title>
                      {s.swap
                        ? `Feistel swap: the two halves cross — the carried half (${s.carryLabel}) and the combined half (${s.mixedLabel}) each move to the opposite side of the next round's split. The port-native cipher realizes this via the recombine's concat argument order, then the next split.`
                        : `No swap (the self-inverse last-round exception): the halves pass straight down — the combined half (${s.mixedLabel}) stays left, the carried half (${s.carryLabel}) stays right.`}
                    </title>
                    {rail(s.carry, s.carryColor, s.carryEdgeKey, s.carryLabel)}
                    {rail(s.mixed, s.mixedColor, s.mixedEdgeKey, s.mixedLabel)}
                    {/* Landing dots — one per rail, at each wire's endpoint on the
                        next round's split, tinted to that rail. Replaces the single
                        (mislocated, source-of-`recombine`-coloured) input-port dot,
                        which is suppressed for a swap-fed split in `portArrivalPoints`.
                        `pointer-events:none` so they never steal the wire's click. */}
                    <circle
                      class="graph-feistel-swap-dot"
                      cx={s.carry.x2}
                      cy={s.carry.y2}
                      r={4}
                      style={{ color: s.carryColor }}
                      pointer-events="none"
                    />
                    <circle
                      class="graph-feistel-swap-dot"
                      cx={s.mixed.x2}
                      cy={s.mixed.y2}
                      r={4}
                      style={{ color: s.mixedColor }}
                      pointer-events="none"
                    />
                    <text
                      class="graph-feistel-swap-label"
                      x={carryMid.x}
                      y={carryMid.y}
                      style={{ color: s.carryColor }}
                    >
                      {s.carryLabel}
                    </text>
                    <text
                      class="graph-feistel-swap-label"
                      x={mixedMid.x}
                      y={mixedMid.y}
                      style={{ color: s.mixedColor }}
                    >
                      {s.mixedLabel}
                    </text>
                  </g>
                );
              }}
            </For>

            {/* Case D (2026-07-12): arrival dots on collapsed containers. A folded
              group / iterate receives arrows (SHA-256's per-round `W`, the
              `blocks → round.0` seed) on its box with no terminus marker; render
              a non-interactive dot per incoming arrow where EdgePath attaches it,
              tinted to the arrow. `pointer-events:none` so it never intercepts a
              chevron / drag on the container beneath. */}
            <For each={[...containerArrivalDots().entries()]}>
              {([, dots]) => (
                <For each={dots}>
                  {(dot) => (
                    <circle
                      class="graph-arrival-dot"
                      cx={dot.x}
                      cy={dot.y}
                      r={4}
                      style={{ color: dot.color }}
                      pointer-events="none"
                    />
                  )}
                </For>
              )}
            </For>

            {/* No Twofish inter-round swap-X overlay: Twofish rounds lay out
              HORIZONTALLY (top-level steps, no outer `rounds` group), so a
              `recombine → next split` swap spans ~2000px up-and-over — a long
              diagonal tangle, not a readable X (unlike DES/Blowfish, whose
              rounds stack vertically for a short clean X). We keep the plain
              `recombine → split` carry edge instead; the 4-rail cell + the
              `recombine` narration ("Swap → (R2′,R3′,R0,R1) … the swap is just
              the concat order") carry the swap story. DES-round-16 precedent. */}

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
    case "port-input-unwired":
      // Universal-port Slice 2.6a: pure port-native leaf has an input
      // port with no `portInputs` binding. Surfaced to the user as a
      // pre-Run warning so they can wire it before clicking Run; the
      // runtime throws if they don't.
      return `Input port '${w.portName}' is not wired — declare it in this step's portInputs map.`;
    case "port-input-unresolvable":
      return w.reason === "missing-node"
        ? `Input port '${w.portName}' references node '${w.targetNode}' which doesn't exist in this scope.`
        : `Input port '${w.portName}' references port '${w.targetPort}' on '${w.targetNode}' but that port isn't an output of that node.`;
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
/**
 * No flash-on-click for this affordance — intentional. We explored
 * adding a green-pulse parallel to the HTML ActionButton primitive
 * (signal-driven `flashing` class), but the click triggers a spec
 * mutation that reconstructs the containers array, and Solid's
 * `<For>` rebuilds child instances when the array references change
 * (we don't carry a stable keyBy here). The new DuplicateGlyph
 * instance starts with `flashing=false`, so the user would see no
 * pulse regardless of how the flash was timed. Reordering
 * `triggerFlash()` before `onDuplicate()` did not help — Solid's
 * batched-update flush still replaces the DOM before the next paint.
 *
 * Crucially, the click's RESULT is intensely visible: a brand-new
 * round group appears mid-canvas (every subsequent round renumbers,
 * the matching decrypt round auto-mirrors). No supplementary "click
 * registered" signal is needed for this affordance.
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

/**
 * "Save as element" affordance for a GROUP container (universal-port Phase 4f,
 * compose-and-save). Captures the group as a reusable composite into the
 * "my elements" library (`captureCompositeFromGroup` → `saveComposite`). Same
 * hover-reveal header-row chip pattern as DuplicateGlyph; `★` glyph (distinct
 * from duplicate's `+`) reads as "add to my elements." The name is collected
 * via a native prompt (v1 — a styled dialog is a trivial follow-up), defaulting
 * to the group's label. A capture error (e.g. a group with a looping container
 * inside) is surfaced via `alert`, not swallowed.
 */
const SaveAsElementGlyph = (props: {
  x: number;
  y: number;
  containerId: string;
  defaultName: string;
}) => (
  <g
    class="graph-save-element-button"
    data-testid={`graph-save-element-${props.containerId}`}
    transform={`translate(${props.x}, ${props.y})`}
    onClick={(e) => {
      e.stopPropagation();
      const name = window.prompt("Name this element", props.defaultName);
      if (name === null || name.trim().length === 0) return;
      try {
        saveComposite(captureCompositeFromGroup(useSpec()(), props.containerId, name.trim()));
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`save as element failed for ${props.containerId}:`, err);
        window.alert(`Could not save element: ${msg}`);
      }
    }}
    onPointerDown={(e) => {
      // Prevent the container's drag-start from claiming the gesture.
      e.stopPropagation();
    }}
    onKeyDown={(e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        e.stopPropagation();
        const name = window.prompt("Name this element", props.defaultName);
        if (name === null || name.trim().length === 0) return;
        try {
          saveComposite(captureCompositeFromGroup(useSpec()(), props.containerId, name.trim()));
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          window.alert(`Could not save element: ${msg}`);
        }
      }
    }}
  >
    <title>Save "{props.defaultName}" as a reusable element</title>
    <circle
      class="graph-save-element-button-circle"
      cx={WARNING_DOT_SIZE / 2}
      cy={WARNING_DOT_SIZE / 2}
      r={WARNING_DOT_SIZE / 2}
    />
    <text
      class="graph-save-element-button-glyph"
      x={WARNING_DOT_SIZE / 2}
      y={WARNING_DOT_SIZE / 2 + 0.5}
      text-anchor="middle"
      dominant-baseline="central"
    >
      ★
    </text>
  </g>
);

/**
 * Per-node reset for a relative pin (draggable-replicas plan Slice 4,
 * 2026-05-19). Visible only when the chip has a `relativePositions`
 * entry — the caller passes `onResetRelativePin` only in that case,
 * which is what gates visibility at the prop level.
 *
 * Placement: top-left corner of the chip. Replicas and block chips
 * suppress `DeleteGlyph` (a replica is a visual reference, not editable),
 * so the corner is free. The glyph is `↺` (counterclockwise arrow,
 * U+21BA) rather than `×` to distinguish RESET from DELETE — `×` is the
 * delete affordance elsewhere in the UI, and reusing it would invite
 * users to click expecting deletion. Tooltip "Reset position" makes
 * the intent explicit.
 *
 * CSS opacity hides the glyph until the parent `.graph-leaf` is
 * hovered (mirrors `.graph-source-colors-reset` button discipline —
 * see `app.css` `.graph-leaf-reset-pin`).
 */
const ResetPinGlyph = (props: {
  x: number;
  y: number;
  /** Step id (synthetic for replicas + chips). Tooltip + testid. */
  stepId: string;
  onReset: () => void;
}) => (
  <g
    class="graph-leaf-reset-pin"
    data-testid={`graph-reset-pin-${props.stepId}`}
    transform={`translate(${props.x}, ${props.y})`}
    onClick={(e) => {
      e.stopPropagation();
      props.onReset();
    }}
    onPointerDown={(e) => {
      // Stop pointerdown too — the chip's startNodeDrag handler is also
      // attached to the leaf <g> and would claim the gesture if this
      // event bubbled up.
      e.stopPropagation();
    }}
    onKeyDown={(e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        e.stopPropagation();
        props.onReset();
      }
    }}
  >
    <title>Reset position</title>
    <circle
      class="graph-leaf-reset-pin-circle"
      cx={WARNING_DOT_SIZE / 2}
      cy={WARNING_DOT_SIZE / 2}
      r={WARNING_DOT_SIZE / 2}
    />
    <text
      class="graph-leaf-reset-pin-glyph"
      x={WARNING_DOT_SIZE / 2}
      y={WARNING_DOT_SIZE / 2 + 0.5}
      text-anchor="middle"
      dominant-baseline="central"
    >
      ↺
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
   * Per-node reset for the relative-pin delta (draggable-replicas plan,
   * Slice 4). Present ⇔ the chip currently has a pin; absent for
   * non-replica leaves and for replicas/chips with no delta. The caller
   * gates the presence with an INLINE REACTIVE expression
   * (`relativePinsMap().has(id) ? fn : undefined`) so the prop appears
   * the moment the user's drag writes a pin and disappears when cleared.
   * Explicit `| undefined` is required because `exactOptionalPropertyTypes`
   * forbids passing `undefined` to a bare optional prop — matching
   * ContainerRect's `onResetAbsolutePin?: (() => void) | undefined`.
   */
  onResetRelativePin?: (() => void) | undefined;
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
  /**
   * ─── Port-wiring (4d-bis, Slice E) ──────────────────────────────────────
   * Declared INPUT port names of this leaf (empty for replicas/chips and any
   * leaf with no inputs). Each becomes a small left-edge "arm" handle.
   */
  inputPorts?: readonly string[];
  /**
   * Per-input-port arrival points — where each port's incoming arrow actually
   * lands on this box, plus the CSS colour of that arrow (2026-07-12). When a
   * port is present, its wiring dot is drawn there (instead of on the fixed left
   * edge) and tinted `color` (via inline `color` + `fill: currentColor`), so the
   * dot both tracks and matches its arrow across the canonical top-to-bottom
   * Feistel/Twofish cells. Ports absent from the map (unbound, or fed by the
   * plaintext pill / a container seed) fall back to the legacy muted left-edge
   * placement. `| undefined` for `exactOptionalPropertyTypes` (the parent passes
   * `map.get(id)`).
   */
  inputPortPoints?: ReadonlyMap<string, { x: number; y: number; color: string }> | undefined;
  /** The input port currently armed on THIS leaf, or null. Highlights its handle. */
  armedPortName?: string | null;
  /**
   * When a wire is armed elsewhere and this leaf is a legal source: the
   * coerce verdict for binding it (`"ok"` | `"coerce"`), else null. Drives the
   * bind-target ring + the right-edge bind handle (red on `"coerce"`).
   */
  wireTarget?: "ok" | "coerce" | null;
  /** Arm an input port on this leaf (toggles off if re-armed). */
  onArmPort?: (portName: string) => void;
  /** Bind the armed port to THIS leaf's legal output (then disarm). */
  onBindHere?: () => void;
}) => {
  // Replica chips inherit their SOURCE's label, which for a collapsed-GROUP
  // source (e.g. AES "Key Expansion") can be longer than a leaf chip's fixed
  // width (LEAF_W). SVG <text> doesn't clip, so a long label would spill past
  // the rect. Truncate the RENDERED text with an ellipsis to fit the box;
  // the full label stays in the <title> tooltip. Only replicas truncate —
  // real leaves are sized by the spec and fit by construction.
  const displayLabel = createMemo(() => {
    if (!props.isReplica) return props.label;
    const maxChars = Math.floor((props.box.w - 8) / LABEL_PX_PER_CHAR);
    if (maxChars >= props.label.length || maxChars < 2) return props.label;
    return `${props.label.slice(0, maxChars - 1)}…`;
  });
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
        // Port-wiring (4d-bis): ring a leaf that's a legal bind target while a
        // wire is armed; the coerce variant tints it to warn of a size mismatch.
        "graph-leaf-wire-target": props.wireTarget === "ok",
        "graph-leaf-wire-target-coerce": props.wireTarget === "coerce",
        "graph-leaf-wire-armed": props.armedPortName != null,
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
        {displayLabel()}
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
      {/* Reset-pin affordance — top-LEFT corner of replicas + chips that
          carry a relative-pin delta. The DeleteGlyph above is suppressed
          for `isReplica`, so the corner is free for this. Presence is
          gated by the parent: `onResetRelativePin` is passed only when
          a pin exists, so the icon doesn't appear on unpinned chips. */}
      <Show when={props.onResetRelativePin !== undefined}>
        <ResetPinGlyph
          x={props.box.x + WARNING_DOT_INSET}
          y={props.box.y + WARNING_DOT_INSET}
          stepId={props.stepId}
          onReset={props.onResetRelativePin as () => void}
        />
      </Show>
      {/* ─── Port-wiring handles (4d-bis, Slice E) ──────────────────────────
          Left-edge "arm" handle per input port (click to start a rewire); a
          right-edge "bind" handle appears when this leaf is a legal source for
          an armed wire (click to complete it). Both stopPropagation so they
          never trigger the leaf's drag/scrub. A larger transparent hit-circle
          sits under each small visible dot so the target is easy to click. */}
      <For each={props.inputPorts ?? []}>
        {(portName, i) => {
          const n = (props.inputPorts ?? []).length;
          // Read `props.box` / the arrival map through thunks, NOT captured
          // consts. `props.box` updates live while the node is dragged; a plain
          // `const cx = props.box.x` here freezes the dots in place because the
          // `<For>` child callback is NOT a reactive scope (the documented "For
          // callbacks aren't reactive scopes" gotcha). The rect/label above read
          // `props.box.*` directly in JSX, so they tracked the drag while these
          // handles were left behind — that was the ghost-dot bug.
          //
          // Preferred position: where this port's incoming arrow actually lands
          // (`inputPortPoints`, tracks the box-edge attach across the vertical-
          // flow Feistel/Twofish cells). Fallback: the legacy evenly-spread
          // left edge, used for ports with no resolvable incoming port-flow edge
          // (unbound, or fed from the plaintext pill / a container seed).
          const arrival = () => props.inputPortPoints?.get(portName);
          const cx = () => arrival()?.x ?? props.box.x;
          const cy = () => arrival()?.y ?? props.box.y + (props.box.h * (i() + 1)) / (n + 1);
          // Tint the resting dot to its incoming arrow's colour (via inline
          // `color` + the `.graph-port-arrived` CSS `fill: currentColor`). Set
          // ONLY `color`, never inline `fill` — an inline `fill` outranks the
          // `:hover` / armed `fill: var(--accent)` stylesheet rules and would
          // kill the wiring-handle highlight. Ports with no incoming arrow keep
          // the muted `var(--muted)` baseline.
          const arrivalColor = () => arrival()?.color;
          return (
            <g
              class="graph-port-handle graph-port-in"
              classList={{
                "graph-port-armed": props.armedPortName === portName,
                "graph-port-arrived": arrivalColor() !== undefined,
              }}
              style={(() => {
                const col = arrivalColor();
                return col !== undefined ? { color: col } : undefined;
              })()}
              data-testid={`graph-port-in-${props.stepId}-${portName}`}
              onPointerDown={(e) => e.stopPropagation()}
              onClick={(e) => {
                e.stopPropagation();
                props.onArmPort?.(portName);
              }}
              // Keyboard parity for biome's useKeyWithClickEvents. The dropdown
              // (`PortWiringEditor`) is the a11y-complete rewire path; this just
              // mirrors the click for anyone who focuses the handle.
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  props.onArmPort?.(portName);
                }
              }}
            >
              <title>{`input port "${portName}" — click to rewire`}</title>
              <circle class="graph-port-hit" cx={cx()} cy={cy()} r={9} />
              <circle class="graph-port-dot" cx={cx()} cy={cy()} r={4} />
            </g>
          );
        }}
      </For>
      {/* Case C (2026-07-12): a REPLICA chip that RECEIVES arrows — i.e. a
          replicated node that has its OWN inputs (SHA-256 `split-H` fed by
          `fetch-H`; RSA `phi` fed by `p-1`/`q-1`) — shows a plain, NON-interactive
          arrival dot where each incoming arrow lands, tinted to that arrow. Real
          leaves get the interactive wiring handles above; replicas are references
          and carry no `inputPorts`, so their arrows would otherwise land on a bare
          chip edge with no terminus marker. `portArrivalPoints` already keys these
          by the replica id (its `visualEdgeTargetId` returns the replica for a
          source→replica edge), so we just render the points it resolved. */}
      <Show when={props.isReplica}>
        <For each={[...(props.inputPortPoints?.entries() ?? [])]}>
          {([, pt]) => (
            <circle
              class="graph-arrival-dot"
              cx={pt.x}
              cy={pt.y}
              r={4}
              style={{ color: pt.color }}
              pointer-events="none"
            />
          )}
        </For>
      </Show>
      <Show when={props.wireTarget != null}>
        <g
          class="graph-port-handle graph-port-bind"
          classList={{ "graph-port-bind-coerce": props.wireTarget === "coerce" }}
          data-testid={`graph-port-bind-${props.stepId}`}
          onPointerDown={(e) => e.stopPropagation()}
          onClick={(e) => {
            e.stopPropagation();
            props.onBindHere?.();
          }}
          // Keyboard parity for biome's useKeyWithClickEvents (see input handle).
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              props.onBindHere?.();
            }
          }}
        >
          <title>
            {props.wireTarget === "coerce"
              ? "wire from here (size mismatch — will coerce)"
              : "wire from here"}
          </title>
          <circle
            class="graph-port-hit"
            cx={props.box.x + props.box.w}
            cy={props.box.y + props.box.h / 2}
            r={9}
          />
          <circle
            class="graph-port-dot"
            cx={props.box.x + props.box.w}
            cy={props.box.y + props.box.h / 2}
            r={4}
          />
        </g>
      </Show>
    </g>
  );
};

/**
 * Synthetic endpoint pill — Slice 1 of the graph-narrative plan.
 *
 * Rounded rectangle (rx = h/2 produces a pill shape) at the canvas left
 * (`side="input"`, labelled "plaintext" / "ciphertext" / "message") or
 * canvas right (`side="output"`, labelled "ciphertext" / "plaintext" /
 * "digest"). Visually distinct from the rectangular leaves so a new
 * viewer reads it as "this is where data enters / exits the cipher",
 * not as another step.
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

/**
 * Synthetic rejoin chip — Phase 6b of the DES + branching primitive
 * plan. Renders the `${roundId}:rejoin` synthetic at the bottom or
 * right edge of a `feistel-round` container (placement chosen by
 * `layoutNode` based on parent flow direction). The rejoin synthetic
 * is not a spec leaf — it's a runtime-emitted frame carrying the
 * combined output of the round's 4-arg combine — so the chip's
 * affordances are deliberately narrower than `LeafRect`:
 *
 *   - No `data-drop-anchor`: palette drops walk past it to the next
 *     ancestor (closest("[data-drop-anchor]") on the container).
 *     Inserting "after the rejoin" doesn't have a sensible spec
 *     meaning — the user is meant to drop into the R track or onto
 *     the round container instead.
 *   - No DeleteGlyph: the chip isn't user-removable.
 *   - No warnings overlay: validation skips synthetic ids by
 *     construction (same as endpoint pills, replicas, block chips).
 *   - No drag handlers: the rejoin's geometry is derived from the
 *     surrounding columns, so a free-position pin would just snap
 *     back on the next layout pass.
 *   - Click scrubs to the rejoin frame (its stepId IS the rejoin id)
 *     AND toggles inspector selection so the 4-arg combine inspector
 *     opens (`Layer 5 detail` per plan).
 *
 * Label uses the "⇄ rejoin" convention shared with `StepList`'s
 * synthetic-rejoin row so the linear and graph views stay visually
 * consistent. A future cipher with a non-swap `combineKind` may want
 * to vary the glyph; the plan defers that to a per-kind glyph table
 * once a second kind ships (today DES is the only Feistel user).
 */

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
  /**
   * Reset affordance — defined only when the container carries an
   * absolute pin in the layout sidecar. The parent passes this as a
   * reactive prop expression (`pinnedMap().has(id) ? fn : undefined`)
   * so the icon appears/disappears the moment the pin is written or
   * cleared. Counterpart to LeafRect's `onResetRelativePin` for the
   * absolute-pin path. Explicit `| undefined` is required because
   * `exactOptionalPropertyTypes` forbids passing `undefined` to a
   * bare optional prop.
   */
  onResetAbsolutePin?: (() => void) | undefined;
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
      {/* Save-as-element affordance — slot 1, for `group` containers only
          (Phase 4f compose-and-save). Captures the group as a reusable
          composite into the palette's "my elements" section. Iterates aren't
          offered (their multi-scope chain bindings don't compose cleanly yet —
          see `captureCompositeFromGroup`'s subtree guard). The header row reads:
          [delete] · [save?] · [duplicate?] · [reset?] · label · … */}
      <Show when={props.container.kind === "group"}>
        <SaveAsElementGlyph
          x={props.box.x + WARNING_DOT_INSET + (WARNING_DOT_SIZE + 4)}
          y={props.box.y + (HEADER_H - WARNING_DOT_SIZE) / 2}
          containerId={props.container.id}
          defaultName={props.container.label}
        />
      </Show>
      {/* Duplicate affordance for AES round groups. Sits to the right of the
          save chip (a round is a group, so save always precedes it), hidden via
          the same hover-reveal CSS pattern. Gated by `isRoundDuplicatable` so
          the final round (no clean counterpart) doesn't render the button. */}
      <Show when={isRoundDuplicatable(props.container.id)}>
        <DuplicateGlyph
          x={
            props.box.x +
            WARNING_DOT_INSET +
            (WARNING_DOT_SIZE + 4) * (props.container.kind === "group" ? 2 : 1)
          }
          y={props.box.y + (HEADER_H - WARNING_DOT_SIZE) / 2}
          containerId={props.container.id}
          onDuplicate={() => duplicateRoundInSpec(props.container.id)}
        />
      </Show>
      {/* Reset-pin affordance — after delete/save/duplicate so the row reads:
          [delete] · [save?] · [duplicate?] · [reset?] · label · …
          Visible only when the parent passed `onResetAbsolutePin`, which it
          does iff this container carries an absolute pin in the layout sidecar.
          Counterpart to LeafRect's per-replica reset. */}
      <Show when={props.onResetAbsolutePin !== undefined}>
        <ResetPinGlyph
          x={
            props.box.x +
            WARNING_DOT_INSET +
            (WARNING_DOT_SIZE + 4) *
              (1 +
                (props.container.kind === "group" ? 1 : 0) +
                (isRoundDuplicatable(props.container.id) ? 1 : 0))
          }
          y={props.box.y + (HEADER_H - WARNING_DOT_SIZE) / 2}
          stepId={props.container.id}
          onReset={props.onResetAbsolutePin as () => void}
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

/**
 * Pixel magnitude of the perpendicular offset applied to the bundle
 * `×N` label so the pill sits next to the arrow shaft rather than on
 * top of it. 16 px is enough to clear a 12-px hit-stroke companion
 * path plus a couple of pixels of breathing room — verified visually
 * on the AES-128 ECB + collapsed + always-replicate fixture during
 * the 2026-05-17 manual smoke.
 */
const LABEL_PERP_OFFSET = 16;

/**
 * Position along the arrow (0 = source, 1 = target) where the bundle
 * `×N` pill anchors. Was 0.5 (midpoint) in the original bundling
 * commit; bumped to 0.25 on 2026-05-17 after user feedback during the
 * polish smoke ("it would be better if the arrow counter is situated
 * near arrow start, not in the middle, because now sometimes it can
 * get obstructed by other replicates"). The midpoint of a long arrow
 * from a row-1+ replica intersects the column of row-0+ replicas;
 * anchoring near the source keeps the pill close to its own chip and
 * out of the intervening replica boxes.
 */
const LABEL_T_ANCHOR = 0.25;

/**
 * Compute the anchor point for a bundle's `×N` pill. Linear
 * interpolation of (sx, sy) → (tx, ty) at `LABEL_T_ANCHOR` (= 0.25,
 * i.e. one quarter along the arrow from the source), then shifted by
 * `LABEL_PERP_OFFSET` along the unit perpendicular `(-dy, dx)/length`.
 * The 90° CCW choice means a downward vertical arrow gets a LEFTWARD
 * label; a rightward horizontal arrow gets a DOWNWARD label — both
 * side-of-shaft, which was the explicit user ask. Falls back to the
 * raw anchor when the direction vector degenerates to zero (defensive;
 * layout never produces zero-length edges in practice).
 */
const perpendicularLabelMidpoint = (
  sx: number,
  sy: number,
  tx: number,
  ty: number,
): { x: number; y: number } => {
  const mx = sx + (tx - sx) * LABEL_T_ANCHOR;
  const my = sy + (ty - sy) * LABEL_T_ANCHOR;
  const dx = tx - sx;
  const dy = ty - sy;
  const length = Math.sqrt(dx * dx + dy * dy);
  if (length < 1) return { x: mx, y: my };
  // Unit perpendicular (90° CCW): for a downward arrow (dx=0, dy>0)
  // this is (-1, 0) → label shifts LEFT. Good direction since the
  // canvas grows rightward and the panel/sidebar already crowds the
  // left, so a leftward nudge keeps the label visually grouped with
  // the source (the replica chip above) rather than with the
  // consumer (the iterate below).
  const px = -dy / length;
  const py = dx / length;
  return { x: mx + px * LABEL_PERP_OFFSET, y: my + py * LABEL_PERP_OFFSET };
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
   * from `consumerPortOffset` so multi-incoming consumers (replicas and
   * non-replicas alike) distribute across the consumer's top edge
   * instead of converging at the midpoint. Defaults to 0, so
   * single-incoming consumers render identically to pre-port-spreading.
   * Only the vertical regime (replica directly above consumer) applies
   * this offset; the horizontal regime applies `targetYOffset` instead.
   */
  targetXOffset?: number;
  /**
   * Port-spreading offset applied to the target attach y in the horizontal
   * regime (source to the left or right of consumer). Same `consumerPortOffset`
   * value as `targetXOffset`, but consumed on the y-axis so multi-incoming
   * edges spread along the consumer's LEFT / RIGHT edge instead of all
   * converging at the vertical midpoint (`toCy`). Defaults to 0. Clamped
   * to `to.h / 2 − 4` inside EdgePath so the attach point stays inside
   * the consumer box even when port-gap math overshoots. The portGap
   * passed in should be height-aware (e.g. `LEAF_H / 4 ≈ 7 px`) — reusing
   * the width-derived `LEAF_W / 10 ≈ 13 px` would pin against the clamp
   * on leaf-shaped consumers (LEAF_H = 28, half-width = 14). The call
   * site is responsible for passing the right magnitude.
   */
  targetYOffset?: number;
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
   * Vertical shift applied to the SOURCE y of the path in the
   * horizontal regime — `sy = fromCy + sourceYOffset`. Mirrors
   * `targetYOffset` so that when a multi-input consumer spreads its N
   * incoming edges across N slots on its left/right edge, the SAME
   * slot offset shifts each edge's source-y on its source chip's
   * right/left edge. Adjacent-source arrows leaving sibling chips at
   * the same row centerline (e.g. SHA-256's `sigma1-r17/r19/s10→sigma1`
   * with 3 adjacent sources) become parallel-shifted lines instead of
   * 3 lines converging on one y, giving each arrow a visibly distinct
   * trajectory through the inter-chip corridor.
   *
   * Slice S2(k) of `docs/plans/sha-256-density-polish.md` (Case B —
   * msg-schedule iteration-body visual overlap). Full-magnitude
   * same-sign per [[feedback_canvas_tool_conventions]]'s "monotonic
   * spread, not alternating" precedent set by `replicaSourceXOffset`.
   *
   * Defaults to 0 → single-incoming consumers and non-port-flow edges
   * render identically to pre-S2(k). Clamped to `from.h / 2 − 4` so
   * the exit point stays inside the source box.
   *
   * Only meaningful in the horizontal regime; ignored in the vertical
   * regime (vertical regime uses `sourceXOffset` for replica edges).
   */
  sourceYOffset?: number;
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
  /**
   * Focus-dim v0 (Slice S2(m) of sha-256-density-polish). When true,
   * this edge fades to ~0.18 opacity via the `graph-edge-dimmed`
   * class on the outer `<g>`. Drives the "click a chip → its
   * incident arrows pop, everything else fades" pedagogy for
   * high-fanout consumers like SHA-256's `final.assemble`. Defaults
   * to false → pre-S2(m) appearance.
   *
   * Applied on the wrapping `<g>` so opacity inherits down to the
   * visible path, start-dot, hit path, and bundle ×N label
   * uniformly. Hit path's clicks still register because CSS opacity
   * does not affect pointer-events (only `pointer-events: none`
   * does).
   */
  dimmed?: boolean;
  /**
   * Number of edges collapsed into this rendered path (the bundle
   * count). Defaults to 1; singletons render identically to the pre-
   * bundle world. For N ≥ 2 the path is rendered with a thicker
   * stroke (logarithmic in N, capped) AND a `×N` text label at the
   * path midpoint. The hit zone stays a single 12 px companion path;
   * the inspector store routes the click to the bundle-summary
   * variant via the `bundle:` data-edge-key prefix.
   */
  bundleCount?: number;
  /**
   * The bundle's aux keys, used to populate the hover/title tooltip
   * when the bundle is multi (N ≥ 2). For singletons this prop is
   * ignored — the existing `auxKey` prop already carries the only
   * key. The renderer joins these for the `<title>` so users can see
   * the full list on hover; the in-app inspector (Slice C) renders the
   * same list with click-to-drill behavior.
   */
  bundleAuxKeysSample?: readonly string[];
  /**
   * Source-color override (2026-05-19). When defined, this CSS color is
   * applied INLINE to the visible path's stroke, the start-dot's fill,
   * and the bundle ×N pill's text — overriding today's kind-based
   * styling for these elements. Undefined means "fall through to the
   * existing kind classes" (the legacy path).
   *
   * The arrowhead marker IS recolored to match — `.graph-arrow-glyph-*`
   * uses SVG2's `context-stroke` fill so the marker resolves to the
   * referencing path's stroke at render time. No prop plumbing needed
   * for arrowheads; they follow the path automatically.
   *
   * The pinned-edge halo is kept consistent via `currentColor`: when
   * `sourceColor` is defined we set `style.color` on the visible path
   * so the higher-specificity CSS rule
   * `.graph-edge-source-colored.graph-edge-selected` resolves
   * `drop-shadow(0 0 4px currentColor)` to the source colour. The
   * plain `.graph-edge-selected` rule uses `var(--accent)` (light
   * blue) — without the override a pinned orange-coded edge would get
   * a light-blue halo, which the user reads as "different element."
   * For uncoloured edges the default accent halo still applies via
   * the original CSS rule (the `.graph-edge-source-colored` class is
   * absent, so the override doesn't match).
   *
   * Explicit `| undefined` (rather than `?:`) because the call site
   * computes the value via an IIFE that returns `string | undefined`;
   * under `exactOptionalPropertyTypes: true` the `?:` form would
   * reject an explicit `undefined` argument.
   */
  sourceColor: string | undefined;
  /**
   * Source-stroke *style* override (A3a, 2026-07-09). When defined, the
   * visible path applies this style's four orthogonal channels
   * (`stroke-dasharray`, `stroke-linecap`, `stroke-dashoffset`, and a
   * `widthMul` that MULTIPLIES — never overwrites — the base density/bundle
   * width). Undefined means "no stroke styling" — the caller already folds
   * the `solid` baseline into `undefined`, so a defined value always changes
   * at least one channel.
   *
   * Orthogonal to `sourceColor`: an edge can be both coloured (its stroke
   * paint) and styled (its dash texture). The width multiplier composes with
   * the existing bundle `stroke-width` math; the dash/linecap/offset are
   * new channels no other prop touches. Like `sourceColor`, an explicit
   * `| undefined` (not `?:`) because the call site returns
   * `StrokeStyle | undefined` from an IIFE under
   * `exactOptionalPropertyTypes`.
   */
  sourceStroke: StrokeStyle | undefined;
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
  // "always right→left" rule. Three regimes:
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
  //   - **Feedback overhead** (exit top / enter top, arcing above): used
  //     for cross-iteration feedback edges (e.g. CBC's
  //     cbc-snapshot → cbc-xor) when they fall outside the vertical
  //     regime. The two boxes are same-row siblings, so the horizontal
  //     regime would crash the feedback head into the consumer's right
  //     edge — exactly where the forward state spine departs.
  //     Structurally rerouting the feedback head to the consumer's TOP
  //     edge separates the head from the spine tail AND draws the
  //     "loops to next iteration" narrative explicitly above the row.
  //     See the `props.isFeedback` branch below for full rationale.
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
  // Returns the SVG path `d` string, the (x, y) position of the start-
  // dot (vertical-regime replica edges only), and the midpoint (used
  // for bundle `×N` label placement). Computed in one memo so the
  // geometry math runs once per change.
  const geom = createMemo<{
    path: string;
    startDot: { x: number; y: number } | null;
    midpoint: { x: number; y: number };
  }>(() => {
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
          // Bundle-label midpoint: shifted perpendicular to the path
          // direction so the pill sits NEXT TO the arrow shaft, not ON
          // it. Without this, an 11-bundle's `×11` pill at the dead
          // center of a vertical arrow completely covers the shaft —
          // user reaction during the 2026-05-17 manual smoke:
          // "I cannot see the arrow." Vector math: take the unit
          // perpendicular `(-dy, dx)/length` (90° CCW rotation of the
          // path direction) and step by `LABEL_PERP_OFFSET`. For a
          // vertical arrow that becomes a horizontal nudge; for a
          // horizontal arrow it becomes a downward nudge. Diagonals
          // shift proportionally on both axes. Falls back to the raw
          // midpoint if `length` is near zero (degenerate edge —
          // shouldn't happen in practice since the layout enforces a
          // gap, but the guard keeps the renderer crash-free).
          midpoint: perpendicularLabelMidpoint(sx, sy, tx, ty),
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
        // Same perpendicular offset as the replica branch above. The
        // cubic Bezier passes through the geometric midpoint by
        // symmetry (control points are symmetric in x); the label
        // sits perpendicular to that point so it's CLEAR of the
        // curve at the midpoint.
        midpoint: perpendicularLabelMidpoint(sx, sy, tx, ty),
      };
    }

    // Feedback-edge override (2026-05-18). When `useVertical` is false
    // but the edge is iterate-feedback (e.g. CBC's
    // cbc-snapshot → cbc-xor; future OFB / CFB will produce the same
    // shape), route the path OVER THE TOP rather than through the
    // horizontal regime's side-arc.
    //
    // **Why.** In CBC the feedback source (cbc-snapshot) and target
    // (cbc-xor) are same-row siblings in the iterate chip body:
    // `horizOverlap=false`, `vertOverlap=true`, so `useVertical=false`
    // is forced. The horizontal regime's natural geometry has the
    // arrowhead enter cbc-xor's RIGHT edge at right-center — the
    // SAME POINT where the forward state spine cbc-xor → add-round-key
    // DEPARTS. Both arrows then share one tiny region on the consumer's
    // right edge (head + tail) and the box visually congests. The user
    // surfaced this on the 2026-05-18 manual smoke after the z-order
    // fix (commit 80cf29a) shipped.
    //
    // **The fix is structural, not a within-edge nudge.** Per the
    // 2026-05-18 design decision: when one edge becomes overcrowded,
    // SWITCH the incoming arrowhead to a different edge entirely. For
    // feedback edges in horizontal regime, the perpendicular TOP edge
    // is the natural choice — it's:
    //   - distinct from the right edge where forward spines depart,
    //   - the conventional "loop overhead" shape for cross-iteration
    //     feedback (CPU pipeline diagrams, dataflow graphs etc.),
    //   - already reinforced by the dashed feedback styling.
    //
    // Unconditional in horizontal regime (per user pick 2026-05-18):
    // the conditional alternative (detect spine-departure occupancy)
    // adds plumbing the practical case never benefits from — every
    // feedback edge today AND every planned cross-iteration mode has
    // a forward spine sibling, so "crowded" is always true. The
    // unconditional rule generalises to OFB / CFB without re-tuning.
    //
    // **Vertical regime feedback edges**: covered above by the
    // `useVertical` early return. They already exit top/bottom of the
    // source and enter top/bottom of the target, so they don't crowd
    // the right edge — no override needed.
    if (props.isFeedback) {
      const fromCx = from.x + from.w / 2;
      const toCx = to.x + to.w / 2;
      // Exit source's TOP edge. Path tangent at t=0 is `(0, -pull)`
      // → leaves the box going UP, which is what we want.
      const sx = fromCx;
      const sy = from.y;
      // Enter target's TOP edge from above. `ARROW_INSET` keeps the
      // arrowhead tip just outside the rectangle stroke so it doesn't
      // visually penetrate the box; the tip itself lands ON the top
      // edge (the marker triangle hangs below the path endpoint).
      const tx = toCx;
      const ty = to.y - ARROW_INSET;
      // Arc height — proportional to horizontal span so a longer
      // overhead loop gets a taller arc clearly distinct from the
      // chip row beneath. Floor at 28 px so even adjacent siblings
      // produce a visible loop above the row.
      const naturalPull = Math.max(28, Math.abs(tx - sx) * 0.35);
      // Canvas-headroom cap (2026-05-18 follow-up). For a symmetric
      // cubic Bezier with control points at (sy − pull) and (ty − pull)
      // and sy ≈ ty, the on-curve peak sits at y = sy − 0.75 × pull
      // (the Bezier point at t = 0.5 with this control geometry).
      // We need `peak ≥ ARC_TOP_INSET` so the arrowhead-most-distant
      // point stays inside the SVG viewBox (which starts at y = 0).
      // Solving sy − 0.75 × pull ≥ ARC_TOP_INSET gives
      // pull ≤ (sy − ARC_TOP_INSET) × 4 / 3.
      //
      // Without this cap, wide-span feedback edges (e.g. a future
      // mode where the cross-iteration source sits many leaves away
      // from the cross-iteration target) drove pull well past the
      // available headroom — the chip row sits at y ≈ 96 (one
      // CANVAS_MARGIN below the top + iterate header), so a pull of
      // ~158 placed the arc peak at y ≈ −62, OUTSIDE the viewBox.
      // The user surfaced this on the 2026-05-18 manual smoke after
      // the first-pass overhead routing landed (commit fdf7fb2).
      //
      // The `Math.max(28, ...)` on `headroomPull` keeps the min-arc
      // floor honoured in the degenerate case where `sy` is unusually
      // small (e.g. the iterate were lifted to row 0 with no
      // CANVAS_MARGIN, which doesn't happen today but keeps the
      // fallback robust). Practically, with sy ≈ 96 the headroom
      // cap is ~115 → narrow CBC cases (pull ≈ 28-52) are unchanged;
      // only the wide cases that were clipping get tamed.
      const ARC_TOP_INSET = 10;
      const headroomPull = Math.max(28, ((sy - ARC_TOP_INSET) * 4) / 3);
      const pull = Math.min(naturalPull, headroomPull);
      // Cubic Bezier with vertical control points above both
      // endpoints. At t=1 the tangent is `(0, +pull)` → arrowhead
      // points DOWN into the target's top edge. The symmetric pull
      // means the arc is left-right symmetric whether the source is
      // to the left or right of the target.
      const c1x = sx;
      const c1y = sy - pull;
      const c2x = tx;
      const c2y = ty - pull;
      // Bundle `×N` pill anchor (`LABEL_T_ANCHOR` = 0.25). For an
      // arc, the linear-interpolation midpoint that
      // `perpendicularLabelMidpoint` returns sits BELOW the curve (on
      // the imaginary chord between source and target). The pill would
      // then float in dead space between the chord and the arc.
      // Compute the actual on-curve Bezier point at t=0.25 so the
      // pill sits visually ON the shaft. Today's CBC feedback edge is
      // a singleton bundle (N=1), so the label doesn't render — but
      // future multi-aux feedback (e.g. a stream-cipher that crosses
      // both prev-ct and prev-keystream into the next block) will
      // need this to read correctly.
      const t = LABEL_T_ANCHOR;
      const oneMinusT = 1 - t;
      const bezAt = (p0: number, p1: number, p2: number, p3: number): number =>
        oneMinusT * oneMinusT * oneMinusT * p0 +
        3 * oneMinusT * oneMinusT * t * p1 +
        3 * oneMinusT * t * t * p2 +
        t * t * t * p3;
      return {
        path: `M ${sx} ${sy} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${tx} ${ty}`,
        // No start-dot — start-dots are a fan-out-replica affordance
        // (vertical regime); the overhead arc doesn't need one because
        // its origin point on the source's top edge is unambiguous
        // (only feedback edges leave that edge).
        startDot: null,
        midpoint: { x: bezAt(sx, c1x, c2x, tx), y: bezAt(sy, c1y, c2y, ty) },
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
    // Source-side port-spreading (Slice S2(k) of sha-256-density-polish,
    // 2026-05-26 — Case B). Shift the source attach y by `sourceYOffset`
    // so a multi-input consumer's N incoming edges leave their N source
    // chips at N distinct y values within each source's right edge,
    // matching the y values they ALSO land at on the consumer's left
    // edge. With both ends shifted by the same slot offset, the curve
    // collapses to a near-straight horizontal line at the slot's y —
    // adjacent-source arrows become parallel-shifted rather than
    // converging-then-diverging at the consumer. Clamped to
    // `from.h / 2 − 4` so the exit point stays inside the source box
    // even on degenerate inputs (matches the target-side clamp pattern
    // a few lines below). For non-port-flow edges and single-incoming
    // consumers, `sourceYOffset` is 0 and `sy = fromCy` exactly as
    // before — legacy AES/Speck/Serpent/DES specs (no horizontal-regime
    // multi-input port-flow combines) render byte-identically.
    const rawSourceY = props.sourceYOffset ?? 0;
    const sourceYCap = from.h / 2 - 4;
    const clampedSourceY = Math.max(-sourceYCap, Math.min(sourceYCap, rawSourceY));
    const sy = fromCy + clampedSourceY;
    const tEdge = rightward ? to.x : to.x + to.w;
    const naturalGap = rightward ? to.x - (from.x + from.w) : from.x - (to.x + to.w);
    const inset = naturalGap > 0 ? Math.min(ARROW_INSET, naturalGap / 2) : ARROW_INSET;
    const tx = rightward ? tEdge - inset : tEdge + inset;
    // Port-spreading on the consumer's LEFT / RIGHT edge: shift `ty` by
    // `targetYOffset` so multi-incoming edges in the horizontal regime
    // spread along the consumer's vertical edge instead of all stacking
    // at `toCy`. Defaults to 0 → single-incoming consumers and pre-fix
    // graphs render unchanged. Clamped to `to.h / 2 − 4` (mirrors the
    // x-clamp pattern at lines 4528–4530) so the attach point stays
    // inside the box even at extreme `localCount` values where the
    // un-clamped offset would exceed half the box height.
    const rawYOffset = props.targetYOffset ?? 0;
    const yOffsetCap = to.h / 2 - 4;
    const clampedYOffset = Math.max(-yOffsetCap, Math.min(yOffsetCap, rawYOffset));
    const ty = toCy + clampedYOffset;
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
      // Perpendicular-offset midpoint — same helper as the vertical
      // regime. For a horizontal arrow the offset becomes a downward
      // nudge so the pill sits beneath the shaft rather than on it.
      midpoint: perpendicularLabelMidpoint(sx, sy, tx, ty),
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
    //
    // The wrapping `<g>` carries `style.color = sourceColor` when
    // colour-coding is active. SVG's `currentColor` inherits down to
    // descendants, so the source-coloured pinned-halo rules (path's
    // and start-dot's `.graph-edge-source-colored.graph-edge-selected`)
    // resolve `drop-shadow(0 0 N currentColor)` to the source colour
    // without per-element style threading. Uncoloured edges leave
    // `color` unset, so the original `var(--accent)` halo rule wins.
    <g
      classList={{ "graph-edge-dimmed": props.dimmed === true }}
      style={props.sourceColor !== undefined ? { color: props.sourceColor } : undefined}
    >
      <path
        class={`graph-edge graph-edge-${props.kind}`}
        classList={{
          "graph-edge-feedback": props.isFeedback,
          "graph-edge-selected": props.isSelected,
          "graph-edge-bundle": (props.bundleCount ?? 1) >= 2,
          "graph-edge-source-colored": props.sourceColor !== undefined,
        }}
        d={geom().path}
        marker-end={`url(#graph-arrow-${props.kind})`}
        pointer-events="none"
        // Inline style.stroke overrides the kind-based CSS rule for any
        // edge whose canonical source has an assigned color. Crucially
        // we DO NOT use the SVG `stroke=""` PRESENTATION ATTRIBUTE here:
        // presentation attributes have the lowest CSS specificity (per
        // the SVG spec they translate to an originating-style rule
        // below any author CSS), so `stroke="#E69F00"` would lose to
        // `.graph-edge-state { stroke: var(--text); }`. The `style`
        // attribute is real inline CSS at the highest specificity, so
        // the assigned color wins.
        //
        // Undefined falls through to the kind class (today's behavior).
        // The `graph-edge-source-colored` class above bumps opacity to
        // 1 for aux edges so the assigned color reads at full
        // saturation; without that override the 0.35 aux baseline
        // would wash out the user-picked color. (The wrapping `<g>`
        // also carries `style.color` so `currentColor` in the
        // source-coloured halo CSS rule resolves to the same value —
        // see the `.graph-edge-source-colored.graph-edge-selected`
        // rule.)
        // Inline style carries three of the four channels: `sourceColor`
        // (the stroke paint, as before), the source-STROKE dash texture
        // (`stroke-dasharray` / `stroke-linecap` / `stroke-dashoffset`), AND
        // — only for the heavy weight tier — the multiplied `stroke-width`.
        // Inline style wins over both the kind class AND
        // `.graph-edge-feedback`'s `4 3` dash (a source dash overrides the
        // feedback dash on the rare cross-iteration edge — acceptable for an
        // opt-in channel).
        //
        // Width is INLINE here (rather than the presentation attribute
        // below) BECAUSE it must beat the `.graph-edge-{aux,state}` base-
        // width class — a presentation attribute has the lowest CSS
        // specificity and would be shadowed by that class, leaving the heavy
        // tier invisible. We only emit it when `widthMul !== 1`: the common
        // (solid / plain-dash) path leaves width to the attribute below, so
        // its today's-behavior emphasis (`:hover` → 2.5, `.selected` → 4,
        // which DO beat the attribute) is untouched. The documented trade-
        // off: a hovered/selected HEAVY edge keeps its heavy width instead of
        // the CSS bump — fine for an opt-in channel.
        style={(() => {
          const color = props.sourceColor;
          const s = props.sourceStroke;
          if (color === undefined && s === undefined) return undefined;
          const out: Record<string, string> = {};
          if (color !== undefined) out.stroke = color;
          if (s !== undefined) {
            // `dasharray === null` is the continuous-line case (only reachable
            // via a heavy/phase tier whose base pattern is solid); skip it so
            // the line stays unbroken.
            if (s.dasharray !== null) out["stroke-dasharray"] = s.dasharray;
            out["stroke-linecap"] = s.linecap;
            if (s.dashoffset !== undefined) out["stroke-dashoffset"] = String(s.dashoffset);
            if (s.widthMul !== 1) {
              const n = props.bundleCount ?? 1;
              // Base = the same density/bundle width the attribute below
              // computes (bundle formula for n≥2, else the per-kind CSS
              // default). The heavy tier MULTIPLIES it — never overwrites —
              // so the density math still wins its part.
              const base =
                n >= 2 ? 1.5 + Math.min(1.5, Math.log2(n) * 0.7) : props.kind === "state" ? 2 : 1.5;
              out["stroke-width"] = String(base * s.widthMul);
            }
          }
          return out;
        })()}
        // Conservative log-based scaling per advisor: N=2 ~2.2 px, N=11
        // ~2.7 px, N=100 ~3.0 px. The `×N` label does most of the
        // communicating; the arrow shouldn't dominate. Falls back to
        // CSS (1.5 px aux / 2 px state) for singleton bundles by
        // returning `undefined`, which SVG treats as "use the
        // stylesheet rule." (The heavy weight tier overrides this via inline
        // style above; the plain/solid path stays on this attribute.)
        stroke-width={(() => {
          const n = props.bundleCount ?? 1;
          if (n < 2) return undefined;
          return 1.5 + Math.min(1.5, Math.log2(n) * 0.7);
        })()}
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
              "graph-edge-source-colored": props.sourceColor !== undefined,
            }}
            cx={dot().x}
            cy={dot().y}
            r={3}
            // Inline style.fill matches the path's stroke when
            // source-coloring is active. As with the path's stroke
            // above, we use `style` rather than the `fill` presentation
            // attribute so the inline color wins over
            // `.graph-edge-start-dot-{aux,state} { fill: var(--text); }`.
            // The `graph-edge-source-colored` class above also routes
            // the pinned-dot halo through the `currentColor` override
            // (matching the path's halo).
            style={props.sourceColor !== undefined ? { fill: props.sourceColor } : undefined}
            pointer-events="none"
          />
        )}
      </Show>
      <path
        class="graph-edge-hit"
        d={geom().path}
        data-edge-key={props.edgeKey}
        data-bundle-count={(props.bundleCount ?? 1).toString()}
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
          {(() => {
            const n = props.bundleCount ?? 1;
            if (n < 2) {
              return `${props.auxKey}${props.isFeedback ? " — feedback (next iteration)" : ""}`;
            }
            // Multi bundle: render the count + the list (truncated for
            // very large bundles so the native tooltip doesn't overflow).
            const sample = props.bundleAuxKeysSample ?? [];
            const previewCap = 6;
            const preview = sample.slice(0, previewCap).join(", ");
            const more = sample.length > previewCap ? `, +${sample.length - previewCap} more` : "";
            const fb = props.isFeedback ? " — feedback (next iteration)" : "";
            return `${n} aux: ${preview}${more}${fb}`;
          })()}
        </title>
      </path>
      {/* ×N label for multi bundles. Rendered LAST so paint order puts
          it on top of both the visible path and the hit path. The
          tspan-on-rect pattern gives a small white background behind
          the text for readability against grid lines / overlapping
          arrows. `pointer-events="none"` lets clicks fall through to
          the hit path beneath. Singleton bundles render no label
          (the `<Show>` guard short-circuits). */}
      <Show when={(props.bundleCount ?? 1) >= 2}>
        {(() => {
          const mp = geom().midpoint;
          const label = `×${props.bundleCount ?? 1}`;
          // Background rect sized to the label width (rough estimate via
          // char count × per-char width). Centered on the midpoint.
          const charW = 6.5;
          const padX = 4;
          const padY = 2;
          const rectW = label.length * charW + padX * 2;
          const rectH = 14;
          return (
            <g class="graph-edge-bundle-label" pointer-events="none">
              <rect
                x={mp.x - rectW / 2}
                y={mp.y - rectH / 2}
                width={rectW}
                height={rectH}
                rx={3}
                ry={3}
                class="graph-edge-bundle-label-bg"
                // Inline style.stroke matches the assigned source color
                // so the pill reads as "part of this source's visual
                // group." Background fill stays at canvas-bg (--bg) for
                // legibility. As with the path/start-dot above, `style`
                // beats presentation attribute when fighting class CSS.
                style={props.sourceColor !== undefined ? { stroke: props.sourceColor } : undefined}
              />
              <text
                x={mp.x}
                y={mp.y + padY}
                text-anchor="middle"
                class="graph-edge-bundle-label-text"
                style={props.sourceColor !== undefined ? { fill: props.sourceColor } : undefined}
              >
                {label}
              </text>
            </g>
          );
        })()}
      </Show>
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
  // Post-Slice-5.1 the only State shape is `bytes` (the matrix4x4-bytes
  // arm retired with the MatrixState shape).
  return formatBytes(state.bytes, fmt);
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
  bundles: () => readonly import("@/core/graph").EdgeBundle[];
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

  // Resolve a bundle-kind target to its `EdgeBundle` (or null if the
  // current bundled graph no longer carries it — e.g. the user
  // re-expanded the iterate so the 11 round-key edges no longer
  // collapse). Lookup is by string key, matching the lookup pattern
  // for edges.
  const activeBundle = createMemo<import("@/core/graph").EdgeBundle | null>(() => {
    const t = props.selectedTarget();
    if (t === null || t.kind !== "bundle") return null;
    const parsed = decodeBundleKey(t.key);
    if (parsed === null) return null;
    for (const b of props.bundles()) {
      if (
        b.from === parsed.from &&
        b.to === parsed.to &&
        b.kind === parsed.kind &&
        b.isFeedback === parsed.isFeedback
      ) {
        return b;
      }
    }
    return null;
  });

  const activeBundleAuxKey = useActiveBundleAuxKey();

  // For a bundle target, the "effective" auxKey is either the user-
  // selected row from the inspector list OR the first auxKey in the
  // bundle (default). The lookup memo below uses this to resolve a
  // GraphEdge representing the active row's flow.
  const effectiveBundleAuxKey = createMemo<string | null>(() => {
    const b = activeBundle();
    if (b === null) return null;
    const picked = activeBundleAuxKey();
    if (picked !== null && b.auxKeys.includes(picked)) return picked;
    return b.auxKeys[0] ?? null;
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
    if (t.kind === "bundle") {
      const b = activeBundle();
      const aux = effectiveBundleAuxKey();
      if (b === null || aux === null) return null;
      // Synthesize a GraphEdge for the active row — `lookupEdgeValue`
      // takes a `GraphEdge` and only reads `from / to / auxKey / kind`,
      // so this carries the same identity the bundle's underlying
      // edges had pre-bundling.
      const syntheticEdge: GraphEdge = {
        from: b.from,
        to: b.to,
        auxKey: aux,
        kind: b.kind,
      };
      return lookupEdgeValue(syntheticEdge, props.spec(), trace, currentBlockIndex);
    }
    return lookupNodeValue(t.id, props.spec(), trace, currentBlockIndex);
  });

  // The representative trace frame for a selected LEAF node — feeds the two
  // leaf-inspector expanders (all port values + what-this-step-does). Null for
  // edges, bundles, endpoint pills, and the ellipsis chip (no single frame).
  // Same tracked deps as `lookup` so it re-resolves on scrub / re-run.
  const nodeFrame = createMemo<import("@/core/types").TraceFrame | null>(() => {
    void props.version();
    const t = props.selectedTarget();
    if (t === null || t.kind !== "node") return null;
    const trace = getTrace();
    const idx = props.frameIndex();
    const currentBlockIndex = trace !== null ? trace.frames[idx]?.blockIndex : undefined;
    return resolveNodeFrame(t.id, props.spec(), trace, currentBlockIndex);
  });

  // Whether the selected leaf's step type has a value-prose narrator. Drives the
  // BRANCH inside the "what this step does" expander: a narrated leaf shows the
  // per-byte `StepNarration`; an un-narrated leaf falls back to the registry's
  // type-prose (what the operation IS) via `StepDescription`.
  const nodeHasNarration = createMemo<boolean>(() => {
    const f = nodeFrame();
    return f !== null && hasNarrationFn(f.stepType);
  });

  // The registry doc (or per-instance `narrationOverride`) for the selected
  // leaf — the type-prose fallback source. Every shipped step registers a doc,
  // so this is defined for real leaves; the guard below stays belt-and-suspenders.
  const nodeOpDoc = createMemo(() => {
    void props.version();
    const f = nodeFrame();
    return f !== null ? resolveStepDoc(props.spec(), f) : undefined;
  });

  // Whether to render the "what this step does" expander at all: true when there
  // is EITHER a value-prose narrator OR a resolvable operation description. This
  // closes the old gap where an un-narrated leaf (AES port-native round steps,
  // plumbing primitives) showed no description whatsoever.
  const nodeHasOpProse = createMemo<boolean>(() => nodeHasNarration() || nodeOpDoc() !== undefined);

  // The always-on cell-provenance map for the selected leaf (Tier B). `"none"`
  // for leaves whose step type has no exact provenance fn (approximate /
  // plumbing / no-input primitives) — the expander then stays hidden.
  const nodeProvenance = createMemo<CellProvenanceSummary>(() => {
    void props.version();
    const f = nodeFrame();
    return f !== null ? summarizeCellProvenance(f) : { kind: "none" };
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
                  when={activeBundle()}
                  fallback={
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
                  }
                >
                  {(bundle) => (
                    <>
                      <span class="graph-value-inspector-from" title={bundle().from}>
                        {bundle().from}
                      </span>
                      <span class="graph-value-inspector-arrow" aria-hidden="true">
                        →
                      </span>
                      <span class="graph-value-inspector-to" title={bundle().to}>
                        {bundle().to}
                      </span>
                      <span class="graph-value-inspector-bundle-count">
                        {`×${bundle().auxKeys.length}`}
                      </span>
                    </>
                  )}
                </Show>
              </div>
              {/* Bundle drill-down — rendered ABOVE the kind/value rows so
                  the user reads the list first, then the active aux's
                  value. Row click sets `activeBundleAuxKey` via the
                  inspector store; the canvas halo stays on the bundle
                  (advisor's recommended "halo stays" semantic). */}
              <Show when={activeBundle()}>
                {(bundle) => (
                  <ul
                    class="graph-value-inspector-bundle-list"
                    data-testid="value-inspector-bundle-list"
                  >
                    <For each={bundle().auxKeys}>
                      {(aux) => (
                        <li
                          class="graph-value-inspector-bundle-row"
                          classList={{
                            "graph-value-inspector-bundle-row-active":
                              effectiveBundleAuxKey() === aux,
                          }}
                          data-aux-key={aux}
                        >
                          <button
                            type="button"
                            class="graph-value-inspector-bundle-row-button"
                            onClick={() => setActiveBundleAuxKey(aux)}
                          >
                            {aux}
                          </button>
                        </li>
                      )}
                    </For>
                  </ul>
                )}
              </Show>
              <Show when={result()}>
                {(r) => (
                  <>
                    <div class="graph-value-inspector-kind-row">
                      <span
                        class={`graph-value-inspector-kind-badge graph-value-inspector-kind-${r().status === "value" || r().status === "endpoint" ? "value" : "info"}`}
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
              {/* Leaf expanders — bring the linear view's per-step surfaces into
                  the graph inspector when a LEAF node is selected. `nodeFrame`
                  is null for edges/bundles/endpoints/ellipsis-chip, so these
                  render only for a resolvable leaf frame. Native <details> so
                  the browser owns open-state (resets per scrub, consistent with
                  the linear panes). */}
              <Show when={nodeFrame()}>
                {(f) => (
                  <div class="graph-value-inspector-expanders">
                    <details class="graph-value-inspector-expander">
                      <summary class="graph-value-inspector-expander-summary">
                        all port values
                      </summary>
                      <div class="graph-value-inspector-expander-body">
                        <PortFlowView frame={f()} />
                      </div>
                    </details>
                    {/* Tier B — the always-on cell input→output map. Shown only
                        when the step type has an exact provenance fn (the
                        approximate / plumbing / no-input primitives resolve to
                        `"none"` and stay hidden — the "missing never wrong"
                        stance the hover already holds). */}
                    <Show when={nodeProvenance().kind !== "none"}>
                      <details class="graph-value-inspector-expander">
                        <summary class="graph-value-inspector-expander-summary">
                          where each byte comes from
                        </summary>
                        <div class="graph-value-inspector-expander-body">
                          <CellProvenanceView frame={f()} summary={nodeProvenance()} />
                        </div>
                      </details>
                    </Show>
                    {/* Tier A — "what this step does". A narrated leaf shows the
                        per-byte value-prose; an un-narrated leaf falls back to
                        the registry's type-prose (what the operation IS) so every
                        leaf carries a description. Guarded on `nodeHasOpProse`
                        (belt-and-suspenders: every shipped step registers a doc). */}
                    <Show when={nodeHasOpProse()}>
                      <details class="graph-value-inspector-expander">
                        <summary class="graph-value-inspector-expander-summary">
                          what this step does
                        </summary>
                        <div class="graph-value-inspector-expander-body">
                          <Show
                            when={nodeHasNarration()}
                            fallback={<StepDescription frame={f()} compact />}
                          >
                            <StepNarration frame={f()} />
                          </Show>
                        </div>
                      </details>
                    </Show>
                  </div>
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
  if (r.status === "aux-fanout") return "aux fan-out";
  // r.status === "value"
  const blockSuffix = r.blockIndex !== undefined ? ` (block ${r.blockIndex})` : "";
  if (r.displayKind === "state") return `state${blockSuffix}`;
  if (r.displayKind === "block-payload") return `block payload${blockSuffix}`;
  return `aux: ${r.auxKey}${blockSuffix}`;
};

/** Render the value-row content for an inspector row. Returns a string;
 *  rich rendering (matrix grid etc.) is intentionally not part of v1.
 *  Endpoint rows format the pill's I/O value (post-run only; pre-run
 *  endpoint clicks have already collapsed to `"no-trace"` in the
 *  lookup). */
const valueRowText = (r: EdgeValueLookup, fmt: ByteFormat): string => {
  switch (r.status) {
    case "endpoint":
      return formatAuxValueOneline(r.value, fmt);
    case "no-trace":
      return "Run the cipher to see values.";
    case "missing":
      return r.reason;
    case "aux-fanout":
      return r.summary;
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
