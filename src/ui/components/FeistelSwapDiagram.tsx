/**
 * Feistel swap diagram — Phase 5 Slice 5.3d (the obligatory port-native rebuild
 * of the old `FeistelMiniDiagram`).
 *
 * A compact SVG rendering the active round's *abstract* Feistel structure:
 * two halves (L | R) → F applied to R (the F-stack) → L ⊕ F → **the swap** →
 * (new_L | new_R). It renders whenever the active frame is inside a port-native
 * Feistel round (detected structurally from the round group's wiring — see
 * `core/feistel-shape.ts`), NOT off the dead `branchPath` the old component
 * used.
 *
 * **The swap crossing is the point.** Port-native DES's per-step chain
 * (split → expand → xor-K → s-boxes → p-permute → xor → concat) hides the one
 * thing this diagram exists to teach: that a Feistel round passes one half
 * through and mixes F into the other, then SWAPS. The crossing is drawn from
 * the round's derived `swap` flag (read from the recombine's actual argument
 * order), so:
 *   - rounds 1..15 (textbook swap) → the wires CROSS (new_L=R, new_R=L⊕F);
 *   - round 16 (the no-swap exception that makes DES self-inverse) → straight
 *     down (new_L=L⊕F, new_R=R).
 * Because `swap` is derived, editing round 16 to swap (or any round to no-swap)
 * updates the picture live — the edit-honesty payoff.
 *
 * Interaction (preserved from the old diagram): clicking an F-stack leaf scrubs
 * the trace to that leaf's frame; the active frame's leaf gets an accent fill.
 * The leaf that consumes a round key (DES's xor-K) gets a K_i subscript that
 * cross-references the round-key panel ribbon below.
 */

import { type FeistelRoundShape, findActiveFeistelRound } from "@/core/feistel-shape";
import { canonicalStepId } from "@/core/step-id";
import type { StepLeaf, TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";

type Props = {
  frame: TraceFrame;
};

const EMPTY_INDEX_MAP: ReadonlyMap<string, number> = new Map();

export const FeistelSwapDiagram = (props: Props) => {
  const spec = useSpec();
  const version = useTraceVersion();

  const active = createMemo(() => findActiveFeistelRound(props.frame, spec()));

  // The F-stack leaf nodes (resolved from the group so we can read each leaf's
  // `roundKeyAux` param for the K_i label). Spec order.
  const fStackLeaves = createMemo<readonly StepLeaf[]>(() => {
    const a = active();
    if (!a) return [];
    const byId = new Map(
      a.group.children
        .filter((c): c is StepLeaf => c.kind === "step")
        .map((l) => [l.id, l] as const),
    );
    return a.shape.fStackIds.flatMap((id) => {
      const leaf = byId.get(id);
      return leaf ? [leaf] : [];
    });
  });

  // Frame index for each F-stack leaf in the active block — drives click-to-
  // scrub. Recomputes on each Run (trace-version) and when the round changes.
  const frameIndexByLeafId = createMemo<ReadonlyMap<string, number>>(() => {
    void version();
    const a = active();
    if (!a) return EMPTY_INDEX_MAP;
    const t = getTrace();
    if (!t) return EMPTY_INDEX_MAP;
    const blockIdx = props.frame.blockIndex;
    const map = new Map<string, number>();
    for (const leaf of fStackLeaves()) {
      for (let i = 0; i < t.frames.length; i++) {
        const f = t.frames[i];
        if (!f) continue;
        if (canonicalStepId(f.stepId) !== leaf.id) continue;
        if (blockIdx === undefined ? f.blockIndex !== undefined : f.blockIndex !== blockIdx) {
          continue;
        }
        map.set(leaf.id, i);
        break;
      }
    }
    return map;
  });

  return (
    <Show when={active()}>
      {(getActive) => (
        <section class="feistel-swap-diagram" aria-label="feistel swap diagram">
          <div class="feistel-swap-diagram-header">
            <span class="feistel-swap-diagram-title">feistel structure</span>
            <code class="feistel-swap-diagram-kind">
              {getActive().shape.swap ? "swap" : "no swap"}
            </code>
          </div>
          <DiagramSvg
            shape={getActive().shape}
            fStackLeaves={fStackLeaves()}
            activeLeafId={canonicalStepId(props.frame.stepId)}
            frameIndexByLeafId={frameIndexByLeafId()}
          />
        </section>
      )}
    </Show>
  );
};

// ─── SVG geometry ─────────────────────────────────────────────────────────

const SVG_WIDTH = 240;
const HALF_W = 52;
const HALF_H = 26;
const L_CX = 44; // left column centre (L_in / new_L)
const R_CX = 196; // right column centre (R_in / new_R)
const FX_CX = 120; // F-stack centre (between the columns)
const LEAF_W = 96;
const LEAF_H = 20;
const LEAF_GAP = 6;
const INPUT_Y = 16;
const F_STACK_Y = INPUT_Y + HALF_H + 22;

const DiagramSvg = (props: {
  shape: FeistelRoundShape;
  fStackLeaves: readonly StepLeaf[];
  activeLeafId: string;
  frameIndexByLeafId: ReadonlyMap<string, number>;
}) => {
  const fStackHeight = (): number => {
    const n = props.fStackLeaves.length;
    if (n === 0) return LEAF_H;
    return n * LEAF_H + (n - 1) * LEAF_GAP;
  };
  const fStackBottom = (): number => F_STACK_Y + fStackHeight();
  const combineY = (): number => fStackBottom() + 26;
  const swapTopY = (): number => combineY() + 14;
  const outputY = (): number => swapTopY() + 40;
  const svgHeight = (): number => outputY() + HALF_H + 12;

  // Output labels: the swap decides which half holds R vs L⊕F. The L⊕F half is
  // the "combined" one and gets the accent.
  const leftLabel = (): string => (props.shape.swap ? "R" : "L⊕F");
  const rightLabel = (): string => (props.shape.swap ? "L⊕F" : "R");

  return (
    <svg
      class="feistel-swap-diagram-svg"
      width={SVG_WIDTH}
      height={svgHeight()}
      viewBox={`0 0 ${SVG_WIDTH} ${svgHeight()}`}
      role="img"
      aria-label={`feistel round, ${props.shape.swap ? "with swap" : "no swap"}`}
    >
      {/* Input halves */}
      <HalfRect cx={L_CX} y={INPUT_Y} label="L" />
      <HalfRect cx={R_CX} y={INPUT_Y} label="R" />

      {/* L straight down into the combine */}
      <line
        x1={L_CX}
        y1={INPUT_Y + HALF_H}
        x2={L_CX}
        y2={combineY()}
        class="feistel-swap-diagram-wire"
      />
      {/* R into the F-stack (fan-out branch 1) */}
      <line
        x1={R_CX}
        y1={INPUT_Y + HALF_H}
        x2={FX_CX}
        y2={F_STACK_Y}
        class="feistel-swap-diagram-wire"
      />
      {/* R passthrough down the right column (fan-out branch 2) */}
      <line
        x1={R_CX}
        y1={INPUT_Y + HALF_H}
        x2={R_CX}
        y2={swapTopY()}
        class="feistel-swap-diagram-wire"
      />

      {/* F-stack — one rect per F-function leaf. */}
      <For each={props.fStackLeaves}>
        {(leaf, i) => (
          <FStackLeaf
            leaf={leaf}
            y={F_STACK_Y + i() * (LEAF_H + LEAF_GAP)}
            isActive={props.activeLeafId === leaf.id}
            frameIndex={props.frameIndexByLeafId.get(leaf.id) ?? null}
            roundKeyIndex={extractRoundKeyIndex(leaf)}
          />
        )}
      </For>
      <Show when={props.fStackLeaves.length === 0}>
        <text
          x={FX_CX}
          y={F_STACK_Y + LEAF_H / 2}
          class="feistel-swap-diagram-empty"
          text-anchor="middle"
          dominant-baseline="middle"
        >
          (empty F)
        </text>
      </Show>

      {/* F output down then left into the combine */}
      <line
        x1={FX_CX}
        y1={fStackBottom()}
        x2={FX_CX}
        y2={combineY()}
        class="feistel-swap-diagram-wire"
      />
      <line
        x1={FX_CX}
        y1={combineY()}
        x2={L_CX + 8}
        y2={combineY()}
        class="feistel-swap-diagram-wire"
      />

      {/* Combine node (L ⊕ F) */}
      <circle cx={L_CX} cy={combineY()} r="8" class="feistel-swap-diagram-combine-node" />
      <text
        x={L_CX}
        y={combineY()}
        class="feistel-swap-diagram-combine-glyph"
        text-anchor="middle"
        dominant-baseline="middle"
      >
        ⊕
      </text>
      {/* L⊕F down into the swap zone */}
      <line
        x1={L_CX}
        y1={combineY() + 8}
        x2={L_CX}
        y2={swapTopY()}
        class="feistel-swap-diagram-wire"
      />

      {/* ─── Swap zone — the crown jewel. Cross (swap) or straight (no-swap). ─── */}
      <SwapWires swap={props.shape.swap} topY={swapTopY()} bottomY={outputY()} />
      <text
        x={SVG_WIDTH / 2}
        y={(swapTopY() + outputY()) / 2}
        class="feistel-swap-diagram-swap-label"
        text-anchor="middle"
        dominant-baseline="middle"
      >
        {props.shape.swap ? "swap" : "no swap"}
      </text>

      {/* Output halves */}
      <HalfRect cx={L_CX} y={outputY()} label={leftLabel()} accent={!props.shape.swap} />
      <HalfRect cx={R_CX} y={outputY()} label={rightLabel()} accent={props.shape.swap} />
    </svg>
  );
};

/** The two swap-zone wires: L⊕F (from left) and R-passthrough (from right). */
const SwapWires = (props: { swap: boolean; topY: number; bottomY: number }) => (
  <>
    {/* L⊕F: left → (right if swap, else left) */}
    <line
      x1={L_CX}
      y1={props.topY}
      x2={props.swap ? R_CX : L_CX}
      y2={props.bottomY}
      class="feistel-swap-diagram-wire feistel-swap-diagram-wire-mix"
    />
    {/* R passthrough: right → (left if swap, else right) */}
    <line
      x1={R_CX}
      y1={props.topY}
      x2={props.swap ? L_CX : R_CX}
      y2={props.bottomY}
      class="feistel-swap-diagram-wire feistel-swap-diagram-wire-pass"
    />
  </>
);

const HalfRect = (props: { cx: number; y: number; label: string; accent?: boolean }) => (
  <g>
    <rect
      x={props.cx - HALF_W / 2}
      y={props.y}
      width={HALF_W}
      height={HALF_H}
      class="feistel-swap-diagram-half"
      classList={{ "feistel-swap-diagram-half-accent": !!props.accent }}
      rx="3"
    />
    <text
      x={props.cx}
      y={props.y + HALF_H / 2}
      class="feistel-swap-diagram-half-label"
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
  roundKeyIndex: number | null;
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
      class="feistel-swap-diagram-leaf-group"
      classList={{
        "feistel-swap-diagram-leaf-active": props.isActive,
        "feistel-swap-diagram-leaf-clickable": isClickable(),
      }}
      onClick={handleClick}
      onKeyDown={handleKey}
      tabindex={isClickable() ? 0 : undefined}
      data-testid={`feistel-swap-diagram-leaf-${props.leaf.id}`}
    >
      <rect
        x={FX_CX - LEAF_W / 2}
        y={props.y}
        width={LEAF_W}
        height={LEAF_H}
        class="feistel-swap-diagram-leaf-rect"
        rx="3"
      >
        <title>{`${props.leaf.id} (${props.leaf.type})`}</title>
      </rect>
      <text
        x={FX_CX}
        y={props.y + LEAF_H / 2}
        class="feistel-swap-diagram-leaf-label"
        text-anchor="middle"
        dominant-baseline="middle"
      >
        {shortName()}
      </text>
      <Show when={props.roundKeyIndex !== null}>
        <text
          x={FX_CX + LEAF_W / 2 + 4}
          y={props.y + LEAF_H / 2}
          class="feistel-swap-diagram-leaf-keyref"
          text-anchor="start"
          dominant-baseline="middle"
          data-testid={`feistel-swap-diagram-keyref-${props.leaf.id}`}
        >
          K
          <tspan baseline-shift="sub" font-size="7">
            {props.roundKeyIndex}
          </tspan>
        </text>
      </Show>
    </g>
  );
};

/**
 * Parse the trailing integer out of a leaf's `params.roundKeyAux` (e.g.
 * "roundKey.4" → 4) so the F-stack leaf that consumes a round key shows a
 * K_i subscript. Returns null when the leaf has no round-key param or the
 * value isn't a `prefix.N` string. Mirrors the old diagram's helper.
 */
const extractRoundKeyIndex = (leaf: StepLeaf): number | null => {
  const p = leaf.params as { roundKeyAux?: unknown };
  if (typeof p.roundKeyAux !== "string") return null;
  const m = /\.(\d+)$/.exec(p.roundKeyAux);
  if (!m || m[1] === undefined) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isInteger(n) ? n : null;
};
