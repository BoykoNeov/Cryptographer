/**
 * Feistel mini diagram — Phase 5b of `docs/plans/des-feistel.md`.
 *
 * A compact SVG (~240×260px) rendering the active Feistel round's
 * *abstract algorithm*: split → F-stack → combine → output. Side-by-
 * side with the FeistelTrackContext panel above StepNarration in
 * linear mode. Renders only when the active frame is inside a Feistel
 * round body (`frame.branchPath` non-empty).
 *
 * Pedagogical headline: the graph view shows spec topology (per-step
 * boxes, aux edges, multi-block iteration). This diagram shows the
 * abstract Feistel structure (two halves, F on one, XOR/add into the
 * other, post-round swap). Side-by-side they teach different lessons —
 * the user reads one to understand "what the runtime is doing", the
 * other to understand "what kind of cipher this is."
 *
 * Cipher-agnostic. The geometry is driven by the active feistel-round
 * spec node's `tracks[*].children.length` and `combineKind`. DES's
 * F-stack has 4 leaves; TEA/XTEA's F has 1; Twofish-style 4-way
 * Feistel would render 4 columns instead of 2. No DES-specific
 * geometry; the file's coordinates parameterize off the spec.
 *
 * Interaction:
 *   - Clicking a leaf in the F-stack scrubs the trace to that leaf's
 *     frame (uses the existing setFrame + the frameIndexByStepId
 *     lookup the rest of the linear view uses).
 *   - The current frame's leaf gets an accent fill so the user knows
 *     where they are in the diagram.
 *
 * Limitations (today):
 *   - 2-track only. Renders only the first 2 tracks; warns muted-style
 *     if the round declares more. Future 4-way Feistel renders as a
 *     follow-up.
 */

import { findStepAndParent } from "@/core/spec-mutations";
import { canonicalStepId } from "@/core/step-id";
import type { CombineKind, FeistelRoundGroup, StepLeaf, TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";

type Props = {
  frame: TraceFrame;
};

/**
 * Resolve the feistel-round spec node containing the active frame.
 * Returns the node + the current track's index. Null when the frame
 * isn't inside a round.
 */
const findActiveRound = (
  frame: TraceFrame,
  spec: ReturnType<typeof useSpec> extends () => infer R ? R : never,
): { round: FeistelRoundGroup; trackIndex: number } | null => {
  const branchPath = frame.branchPath;
  if (!branchPath || branchPath.length === 0) return null;
  const trackName = branchPath[branchPath.length - 1];
  if (trackName === undefined) return null;
  const roundId = frame.path[frame.path.length - 1];
  if (roundId === undefined) return null;
  const located = findStepAndParent(spec, roundId);
  if (!located || located.node.kind !== "feistel-round") return null;
  const round = located.node;
  // Resolve the track index from the track name. Match by `name` first,
  // fall back to stringified index for unnamed tracks (toy specs may
  // omit names).
  const trackIndex = round.tracks.findIndex((t, i) => (t.name ?? String(i)) === trackName);
  if (trackIndex === -1) return null;
  return { round, trackIndex };
};

/**
 * Frame-index lookup for a leaf inside a feistel-round track, given
 * the active frame's blockIndex (for iterate-nested rounds). Returns
 * null when the leaf has no matching frame.
 */
const findLeafFrameIndex = (
  leafId: string,
  trackName: string,
  blockIndex: number | undefined,
  frames: readonly TraceFrame[],
): number | null => {
  // Frames inside a track carry the `:t{name}` suffix and optional
  // `:b{i}`. canonicalStepId would strip both — match on the leaf's
  // own id by walking frames and checking the canonicalized stepId.
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];
    if (!f) continue;
    if (canonicalStepId(f.stepId) !== leafId) continue;
    if (blockIndex === undefined ? f.blockIndex !== undefined : f.blockIndex !== blockIndex) {
      continue;
    }
    // Track membership check: branchPath must end with the requested
    // track name. Ensures we don't pick up a leaf from the OTHER track
    // (impossible today since leaf ids are unique per track, but the
    // check is cheap insurance for future ciphers with non-unique
    // leaf names across tracks).
    if (!f.branchPath || f.branchPath[f.branchPath.length - 1] !== trackName) continue;
    return i;
  }
  return null;
};

export const FeistelMiniDiagram = (props: Props) => {
  const spec = useSpec();
  const version = useTraceVersion();

  const active = createMemo(() => findActiveRound(props.frame, spec()));

  // Frame-index lookup map for every leaf in BOTH tracks. Recomputes on
  // trace version change (each Run). Keyed by leaf id; values are the
  // first matching frame index for the leaf in the round's current
  // block (when the round is inside an iterate). Allocation-free fast
  // path when there's no active round.
  const leafFrameIndexByLeafId = createMemo<ReadonlyMap<string, number>>(() => {
    void version();
    const a = active();
    if (!a) return EMPTY_INDEX_MAP;
    const t = getTrace();
    if (!t) return EMPTY_INDEX_MAP;
    const blockIdx = props.frame.blockIndex;
    const map = new Map<string, number>();
    for (let ti = 0; ti < a.round.tracks.length; ti++) {
      const track = a.round.tracks[ti];
      if (!track) continue;
      const trackName = track.name ?? String(ti);
      for (const leaf of track.children) {
        if (leaf.kind !== "step") continue;
        const idx = findLeafFrameIndex(leaf.id, trackName, blockIdx, t.frames);
        if (idx !== null) map.set(leaf.id, idx);
      }
    }
    return map;
  });

  return (
    <Show when={active()}>
      {(getActive) => (
        <section class="feistel-mini-diagram" aria-label="feistel mini diagram">
          <div class="feistel-mini-diagram-header">
            <span class="feistel-mini-diagram-title">abstract structure</span>
            <code class="feistel-mini-diagram-kind">{getActive().round.combineKind}</code>
          </div>
          <DiagramSvg
            round={getActive().round}
            activeFrameStepId={canonicalStepId(props.frame.stepId)}
            leafFrameIndexByLeafId={leafFrameIndexByLeafId()}
          />
        </section>
      )}
    </Show>
  );
};

const EMPTY_INDEX_MAP: ReadonlyMap<string, number> = new Map();

// ─── SVG layout constants ────────────────────────────────────────────

const SVG_WIDTH = 240;
const HALF_WIDTH = 50;
const HALF_HEIGHT = 28;
const LEAF_WIDTH = 96;
const LEAF_HEIGHT = 22;
const LEAF_GAP = 6;
const L_X = 28;
const R_X = SVG_WIDTH - L_X - HALF_WIDTH;
const F_STACK_X = SVG_WIDTH - L_X - LEAF_WIDTH;
const INPUT_Y = 20;
const F_STACK_Y = INPUT_Y + HALF_HEIGHT + 18;

const DiagramSvg = (props: {
  round: FeistelRoundGroup;
  activeFrameStepId: string;
  leafFrameIndexByLeafId: ReadonlyMap<string, number>;
}) => {
  // Render only tracks 0 + 1 (2-track Feistel). A round with more would
  // still render the first two; the warning at the bottom surfaces the
  // limitation.
  const lTrack = (): FeistelRoundGroup["tracks"][number] | undefined => props.round.tracks[0];
  const rTrack = (): FeistelRoundGroup["tracks"][number] | undefined => props.round.tracks[1];

  // F-stack derived from the R track's leaves. Filter to step leaves
  // (skip any nested groups, though the toy/DES specs don't have them).
  const fStackLeaves = createMemo<readonly StepLeaf[]>(() => {
    const r = rTrack();
    if (!r) return [];
    return r.children.filter((c): c is StepLeaf => c.kind === "step");
  });

  const fStackHeight = (): number => {
    const n = fStackLeaves().length;
    if (n === 0) return LEAF_HEIGHT;
    return n * LEAF_HEIGHT + (n - 1) * LEAF_GAP;
  };

  const combineY = (): number => F_STACK_Y + fStackHeight() + 22;
  const outputY = (): number => combineY() + 32;
  const svgHeight = (): number => outputY() + HALF_HEIGHT + 12;

  // Output labels derived from combineKind. For feistel-standard the
  // swap puts R below L's column and L⊕F below R's column. The labels
  // come from formula text rather than hardcoded per kind.
  const outputLabels = createMemo(() => deriveOutputLabels(props.round.combineKind));

  return (
    <svg
      class="feistel-mini-diagram-svg"
      width={SVG_WIDTH}
      height={svgHeight()}
      viewBox={`0 0 ${SVG_WIDTH} ${svgHeight()}`}
      role="img"
      aria-label={`feistel ${props.round.combineKind} round diagram`}
    >
      {/* Input halves */}
      <HalfRect x={L_X} y={INPUT_Y} label={lTrack()?.name ?? "L"} />
      <HalfRect x={R_X} y={INPUT_Y} label={rTrack()?.name ?? "R"} />

      {/* Vertical lines down from each half */}
      <line
        x1={L_X + HALF_WIDTH / 2}
        y1={INPUT_Y + HALF_HEIGHT}
        x2={L_X + HALF_WIDTH / 2}
        y2={combineY()}
        class="feistel-mini-diagram-wire"
      />
      <line
        x1={R_X + HALF_WIDTH / 2}
        y1={INPUT_Y + HALF_HEIGHT}
        x2={F_STACK_X + LEAF_WIDTH / 2}
        y2={F_STACK_Y}
        class="feistel-mini-diagram-wire"
      />

      {/* F-stack — one rect per R-track leaf */}
      <For each={fStackLeaves()}>
        {(leaf, i) => (
          <FStackLeaf
            leaf={leaf}
            y={F_STACK_Y + i() * (LEAF_HEIGHT + LEAF_GAP)}
            isActive={props.activeFrameStepId === leaf.id}
            frameIndex={props.leafFrameIndexByLeafId.get(leaf.id) ?? null}
          />
        )}
      </For>
      <Show when={fStackLeaves().length === 0}>
        <text
          x={F_STACK_X + LEAF_WIDTH / 2}
          y={F_STACK_Y + LEAF_HEIGHT / 2}
          class="feistel-mini-diagram-empty-track"
          text-anchor="middle"
          dominant-baseline="middle"
        >
          (empty F)
        </text>
      </Show>

      {/* F output wire down to the combine */}
      <line
        x1={F_STACK_X + LEAF_WIDTH / 2}
        y1={F_STACK_Y + fStackHeight()}
        x2={F_STACK_X + LEAF_WIDTH / 2}
        y2={combineY()}
        class="feistel-mini-diagram-wire"
      />

      {/* Combine node — small circle with the combine glyph */}
      <CombineNode x={L_X + HALF_WIDTH / 2} y={combineY()} combineKind={props.round.combineKind} />

      {/* Horizontal wire from F output across to the combine */}
      <line
        x1={F_STACK_X + LEAF_WIDTH / 2}
        y1={combineY()}
        x2={L_X + HALF_WIDTH / 2 + 8}
        y2={combineY()}
        class="feistel-mini-diagram-wire"
      />

      {/* Output halves */}
      <HalfRect
        x={L_X}
        y={outputY()}
        label={outputLabels().leftLabel}
        accent={outputLabels().leftIsCombined}
      />
      <HalfRect
        x={R_X}
        y={outputY()}
        label={outputLabels().rightLabel}
        accent={outputLabels().rightIsCombined}
      />

      {/* Wires down from combine to outputs */}
      <line
        x1={L_X + HALF_WIDTH / 2}
        y1={combineY() + 8}
        x2={L_X + HALF_WIDTH / 2}
        y2={outputY()}
        class="feistel-mini-diagram-wire"
      />
      <line
        x1={L_X + HALF_WIDTH / 2}
        y1={(combineY() + outputY()) / 2}
        x2={R_X + HALF_WIDTH / 2}
        y2={(combineY() + outputY()) / 2}
        class="feistel-mini-diagram-wire"
      />
      <line
        x1={R_X + HALF_WIDTH / 2}
        y1={(combineY() + outputY()) / 2}
        x2={R_X + HALF_WIDTH / 2}
        y2={outputY()}
        class="feistel-mini-diagram-wire"
      />

      <Show when={props.round.tracks.length > 2}>
        <text
          x={SVG_WIDTH / 2}
          y={svgHeight() - 4}
          class="feistel-mini-diagram-warning"
          text-anchor="middle"
        >
          ({props.round.tracks.length}-way Feistel — diagram shows tracks 0 + 1 only)
        </text>
      </Show>
    </svg>
  );
};

/**
 * Compute output labels from the combine kind. For each kind we derive
 * which output half is the "combined" one (gets the accent) vs the
 * passthrough one.
 *
 * The label strings are short — readable inside the 50×28 half rect.
 * Long forms ("L_in XOR R_out", "L_in + R_out") would overflow.
 */
const deriveOutputLabels = (
  kind: CombineKind,
): {
  leftLabel: string;
  rightLabel: string;
  leftIsCombined: boolean;
  rightIsCombined: boolean;
} => {
  switch (kind) {
    case "feistel-standard":
      // new_L = R_in (passthrough); new_R = L_in XOR R_out (combined)
      return {
        leftLabel: "R",
        rightLabel: "L⊕F",
        leftIsCombined: false,
        rightIsCombined: true,
      };
    case "feistel-no-swap":
      // new_L = L_in XOR R_out (combined); new_R = R_in (passthrough)
      return {
        leftLabel: "L⊕F",
        rightLabel: "R",
        leftIsCombined: true,
        rightIsCombined: false,
      };
    case "feistel-add-into-left":
      return {
        leftLabel: "L+F",
        rightLabel: "R",
        leftIsCombined: true,
        rightIsCombined: false,
      };
    case "feistel-add-into-right":
      return {
        leftLabel: "L",
        rightLabel: "R+L",
        leftIsCombined: false,
        rightIsCombined: true,
      };
  }
};

const HalfRect = (props: { x: number; y: number; label: string; accent?: boolean }) => (
  <g>
    <rect
      x={props.x}
      y={props.y}
      width={HALF_WIDTH}
      height={HALF_HEIGHT}
      class="feistel-mini-diagram-half"
      classList={{ "feistel-mini-diagram-half-accent": !!props.accent }}
      rx="3"
    />
    <text
      x={props.x + HALF_WIDTH / 2}
      y={props.y + HALF_HEIGHT / 2}
      class="feistel-mini-diagram-half-label"
      text-anchor="middle"
      dominant-baseline="middle"
    >
      {props.label}
    </text>
  </g>
);

const FStackLeaf = (props: {
  leaf: StepLeaf;
  y: number;
  isActive: boolean;
  frameIndex: number | null;
}) => {
  const shortName = (): string => props.leaf.id.split(".").pop() ?? props.leaf.id;
  const isClickable = (): boolean => props.frameIndex !== null;

  const handleClick = (): void => {
    if (props.frameIndex !== null) setFrame(props.frameIndex);
  };
  const handleKey = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleClick();
    }
  };

  return (
    <g
      class="feistel-mini-diagram-leaf-group"
      classList={{
        "feistel-mini-diagram-leaf-active": props.isActive,
        "feistel-mini-diagram-leaf-clickable": isClickable(),
      }}
      onClick={handleClick}
      onKeyDown={handleKey}
      tabindex={isClickable() ? 0 : undefined}
    >
      <rect
        x={F_STACK_X}
        y={props.y}
        width={LEAF_WIDTH}
        height={LEAF_HEIGHT}
        class="feistel-mini-diagram-leaf-rect"
        rx="3"
      >
        <title>{`${props.leaf.id} (${props.leaf.type})`}</title>
      </rect>
      <text
        x={F_STACK_X + LEAF_WIDTH / 2}
        y={props.y + LEAF_HEIGHT / 2}
        class="feistel-mini-diagram-leaf-label"
        text-anchor="middle"
        dominant-baseline="middle"
      >
        {shortName()}
      </text>
    </g>
  );
};

/**
 * Combine node — small circle with a per-kind glyph. ⊕ for XOR-based
 * combines (feistel-standard / no-swap), + for the add variants.
 */
const CombineNode = (props: { x: number; y: number; combineKind: CombineKind }) => {
  const glyph = (): string => {
    if (props.combineKind === "feistel-standard" || props.combineKind === "feistel-no-swap") {
      return "⊕";
    }
    return "+";
  };
  return (
    <g>
      <circle cx={props.x} cy={props.y} r="8" class="feistel-mini-diagram-combine-node" />
      <text
        x={props.x}
        y={props.y}
        class="feistel-mini-diagram-combine-glyph"
        text-anchor="middle"
        dominant-baseline="middle"
      >
        {glyph()}
      </text>
    </g>
  );
};
