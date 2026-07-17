/**
 * Twofish round diagram — the linear view's *abstract* picture of a Twofish
 * round, and the 4-rail sibling of `FeistelSwapDiagram`.
 *
 * Twofish is not the 2-way Feistel form, so `analyzeFeistelRound` returns null
 * for its 4-input recombine and the whole 2-way linear trio stays dark. This
 * component fills that gap: it self-detects a port-native Twofish round from the
 * round group's wiring (`core/twofish-shape.ts`) and renders nothing otherwise,
 * so it is inert for every other cipher.
 *
 * **What it teaches — the swap.** Scrubbing the round's ~28 leaves one at a time
 * (split → g → g → PHT → rotate → xor → concat) hides the shape: that two of the
 * four words get mixed while the other two ride through untouched, and that the
 * round ENDS by rotating all four — `concat(R2′, R3′, R0, R1)`. The mixed pair
 * moves to the front, the carried pair to the back. That 4-way rotation is
 * Twofish's answer to the 2-way Feistel crossing, and here it is four short
 * labeled wires. (The graph view deliberately omits it: Twofish rounds lay out
 * horizontally ~2000px apart, so the same wires span the canvas and read as a
 * tangle — see `docs/plans/polished-imagining-bird.md`. A single-round diagram
 * has no such problem, which makes the linear view the swap's honest home.)
 *
 * Everything drawn is derived from real wiring (`core/twofish-diagram.ts`), so
 * the encrypt and decrypt rounds — which differ in their two 1-bit rotations and
 * the order those sit on the rails — both render correctly, and a user rewire
 * moves the picture.
 *
 * Interaction mirrors `FeistelSwapDiagram`: the element containing the active
 * leaf is accented ("you are here"), and clicking an element scrubs the trace to
 * its frame. Composite elements (the two g boxes, the PHT) scrub to their first
 * leaf — the diagram is deliberately ABOVE per-leaf altitude; the graph view's
 * canonical cell is where g's interior is already drawn leaf-by-leaf.
 */

import { canonicalStepId } from "@/core/step-id";
import { type TwofishDiagramModel, twofishDiagramModel } from "@/core/twofish-diagram";
import { findActiveTwofishRound } from "@/core/twofish-shape";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";

type Props = {
  frame: TraceFrame;
};

const EMPTY_INDEX_MAP: ReadonlyMap<string, number> = new Map();

export const TwofishRoundDiagram = (props: Props) => {
  const spec = useSpec();
  const version = useTraceVersion();

  const model = createMemo<TwofishDiagramModel | null>(() => {
    const active = findActiveTwofishRound(props.frame, spec());
    if (!active) return null;
    return twofishDiagramModel(active.shape, active.group);
  });

  // Every leaf the diagram can scrub to, so one trace scan serves all elements.
  const scrubIds = createMemo<readonly string[]>(() => {
    const m = model();
    if (!m) return [];
    return [
      m.splitId,
      m.rolNodeId,
      ...m.g0Ids,
      ...m.g1Ids,
      ...m.phtIds,
      ...m.mixRails.flatMap((r) => r.nodes.map((n) => n.id)),
      m.recombineId,
    ];
  });

  // Frame index per leaf in the ACTIVE block — drives click-to-scrub. Recomputes
  // on each Run (trace-version) and when the round changes. Same shape as
  // `FeistelSwapDiagram`'s memo, including the block-index match so a multi-block
  // trace scrubs within the block the user is looking at.
  const frameIndexByLeafId = createMemo<ReadonlyMap<string, number>>(() => {
    void version();
    const ids = scrubIds();
    if (ids.length === 0) return EMPTY_INDEX_MAP;
    const t = getTrace();
    if (!t) return EMPTY_INDEX_MAP;
    const blockIdx = props.frame.blockIndex;
    const wanted = new Set(ids);
    const map = new Map<string, number>();
    for (let i = 0; i < t.frames.length; i++) {
      const f = t.frames[i];
      if (!f) continue;
      const id = canonicalStepId(f.stepId);
      if (!wanted.has(id) || map.has(id)) continue;
      if (blockIdx === undefined ? f.blockIndex !== undefined : f.blockIndex !== blockIdx) continue;
      map.set(id, i);
    }
    return map;
  });

  return (
    <Show when={model()}>
      {(getModel) => (
        <section class="twofish-round-diagram" aria-label="twofish round diagram">
          <div class="twofish-round-diagram-header">
            <span class="twofish-round-diagram-title">twofish round structure</span>
            <code class="twofish-round-diagram-kind">4-way swap</code>
          </div>
          <DiagramSvg
            model={getModel()}
            activeLeafId={canonicalStepId(props.frame.stepId)}
            frameIndexByLeafId={frameIndexByLeafId()}
          />
          <p class="twofish-round-diagram-note muted small">
            Two words are mixed (<code>R2</code>, <code>R3</code>); two ride through untouched (
            <code>R0</code>, <code>R1</code>). The round ends by rotating all four —{" "}
            <code>concat({getModel().outputLabels.join(", ")})</code> — so this round's carried pair
            becomes the next round's mixed pair. That argument order IS the swap.
          </p>
        </section>
      )}
    </Show>
  );
};

// ─── SVG geometry ─────────────────────────────────────────────────────────
// Four evenly-spaced rails (the swap wires need even spacing to read as a
// rotation). The g/PHT machinery hangs off rails 0-1; the mix nodes off rails
// 2-3.
//
// Two routing rules, both learned from looking at this in a browser — a wire
// that merely CROSSES another wire reads fine (every circuit diagram does it),
// but a wire that passes through a labelled BOX reads as a connection that
// isn't there:
//   - The carried words branch off around the g/PHT block — R0 to its left, R1
//     to its right — so neither passes behind the PHT. They stay on their
//     detour all the way into the swap rather than zigzagging back to the rail.
//   - F0/F1 leave the PHT into their own horizontal lane, then drop down clear
//     of every mix chip and enter their target ⊕ from the side. Routing them
//     straight across at their target's height sent F1 through rail 2's
//     rotation chip, which read as "ROR 1 feeds ⊕ F1" — a lie.

const SVG_WIDTH = 440;
const RAIL_X = [66, 176, 286, 396] as const;

const WORD_W = 74;
const WORD_H = 24;
const INPUT_Y = 14;
const INPUT_BOTTOM = INPUT_Y + WORD_H;

/** The carried words' detour lanes, relative to their rail: R0 left, R1 right. */
const CARRY_DX = [-46, 46] as const;
const CARRY_TOP_Y = 60;

const CHIP_W = 64;
const CHIP_H = 18;
const ROL_Y = 56;

const G_W = 64;
const G_H = 44;
const G_Y = 88;
const G_BOTTOM = G_Y + G_H;

// The PHT is deliberately NARROW (T0 and T1 angle inward into it) rather than
// spanning both g columns: a full-span box would sit across R1's carry lane.
const PHT_Y = 154;
const PHT_H = 26;
const PHT_BOTTOM = PHT_Y + PHT_H;
const PHT_CX = (RAIL_X[0] + RAIL_X[1]) / 2;
const PHT_W = 76;
const PHT_LEFT = PHT_CX - PHT_W / 2;
const PHT_RIGHT = PHT_CX + PHT_W / 2;
const F0_X = PHT_LEFT + 18;
const F1_X = PHT_RIGHT - 18;
/** Where T0 / T1 enter the PHT's top edge. */
const T0_IN_X = PHT_LEFT + 18;
const T1_IN_X = PHT_RIGHT - 18;

const MIX_NODE_H = 20;
const MIX_Y0 = 210;
const MIX_ROW_GAP = 40;

/** Each F's own horizontal lane, run below the PHT and above every mix chip. */
const F_LANE_Y = [190, 198] as const;
/** How far left of its target chip an F wire drops down. */
const F_DROP_INSET = 52;

const SWAP_TOP = 286;
const OUT_Y = 330;
const SVG_HEIGHT = OUT_Y + WORD_H + 12;

/** The y of a mix rail's node at index `i`. */
const mixNodeY = (i: number): number => MIX_Y0 + i * MIX_ROW_GAP;

/** The x of carried rail `i`'s detour lane. */
const carryX = (i: 0 | 1): number => (RAIL_X[i] ?? 0) + CARRY_DX[i];

const DiagramSvg = (props: {
  model: TwofishDiagramModel;
  activeLeafId: string;
  frameIndexByLeafId: ReadonlyMap<string, number>;
}) => {
  const m = (): TwofishDiagramModel => props.model;

  // The mix rails, paired with the x of the rail they actually mix (derived —
  // never assumed to be rails 2/3, so a rewired round still draws honestly).
  // A memo because it's read from two places in the JSX below.
  const railsWithX = createMemo(() =>
    m().mixRails.map((rail) => ({
      rail,
      x: RAIL_X[rail.railIndex] ?? RAIL_X[2],
    })),
  );

  // Where each F lands: the y of the xor node that consumes it, on the rail that
  // genuinely mixes it (matched via the rail's derived `fIndex`, not rail order).
  const fTarget = (fIndex: 0 | 1): { x: number; y: number } | null => {
    const entry = railsWithX().find((e) => e.rail.fIndex === fIndex);
    if (!entry) return null;
    const xorIdx = entry.rail.nodes.findIndex((n) => n.kind === "xor");
    if (xorIdx < 0) return null;
    return { x: entry.x, y: mixNodeY(xorIdx) + MIX_NODE_H / 2 };
  };

  // A swap wire starts where its value actually sits: the mixed pair on their
  // rails, the carried pair out on the detour lane they rode down.
  const swapOriginX = (slot: number): number => {
    const src = m().swapSources[slot] ?? slot;
    if (slot >= 2 && (src === 0 || src === 1)) return carryX(src);
    return RAIL_X[src] ?? 0;
  };

  return (
    <svg
      class="twofish-round-diagram-svg"
      width={SVG_WIDTH}
      height={SVG_HEIGHT}
      viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
      role="img"
      aria-label="twofish round: two words through g and the PHT, two carried, then the 4-way swap"
    >
      {/* ─── Input words R0..R3 ─── */}
      <For each={[0, 1, 2, 3]}>
        {(i) => (
          <WordRect
            cx={RAIL_X[i] ?? 0}
            y={INPUT_Y}
            label={`R${i}`}
            id={m().splitId}
            {...props}
            testid={`twofish-round-diagram-input-${i}`}
          />
        )}
      </For>

      {/* ─── The two carried words: branch off and ride their detour lane down
              past the g/PHT block, straight into the swap. ─── */}
      <For each={[0, 1] as const}>
        {(i) => (
          <polyline
            points={`${RAIL_X[i]},${INPUT_BOTTOM} ${carryX(i)},${CARRY_TOP_Y} ${carryX(i)},${SWAP_TOP}`}
            class="twofish-round-diagram-wire twofish-round-diagram-wire-carry"
            fill="none"
          />
        )}
      </For>

      {/* ─── Rail 0: R0 → g0 ─── */}
      <line
        x1={RAIL_X[0]}
        y1={INPUT_BOTTOM}
        x2={RAIL_X[0]}
        y2={G_Y}
        class="twofish-round-diagram-wire"
      />
      <BoxElement
        cx={RAIL_X[0] ?? 0}
        y={G_Y}
        w={G_W}
        h={G_H}
        label="g"
        ids={m().g0Ids}
        {...props}
        testid="twofish-round-diagram-g0"
      />

      {/* ─── Rail 1: R1 → ROL 8 → g1. The rotation rides ATOP the g box, never
              inside it: g0 has no such rotation, and a learner must not read the
              8-bit turn as part of g. ─── */}
      <line
        x1={RAIL_X[1]}
        y1={INPUT_BOTTOM}
        x2={RAIL_X[1]}
        y2={ROL_Y}
        class="twofish-round-diagram-wire"
      />
      <ChipElement
        cx={RAIL_X[1] ?? 0}
        y={ROL_Y}
        w={CHIP_W}
        label={m().rolLabel}
        ids={[m().rolNodeId]}
        {...props}
        testid="twofish-round-diagram-rol"
      />
      <line
        x1={RAIL_X[1]}
        y1={ROL_Y + CHIP_H}
        x2={RAIL_X[1]}
        y2={G_Y}
        class="twofish-round-diagram-wire"
      />
      <BoxElement
        cx={RAIL_X[1] ?? 0}
        y={G_Y}
        w={G_W}
        h={G_H}
        label="g"
        ids={m().g1Ids}
        {...props}
        testid="twofish-round-diagram-g1"
      />

      {/* ─── T0 / T1 angle inward into the PHT. Each name rides ON the wire
              carrying that value — the space beside the g boxes belongs to the
              carry lanes. ─── */}
      <line
        x1={RAIL_X[0]}
        y1={G_BOTTOM}
        x2={T0_IN_X}
        y2={PHT_Y}
        class="twofish-round-diagram-wire"
      />
      <text
        x={(RAIL_X[0] + T0_IN_X) / 2 + 4}
        y={(G_BOTTOM + PHT_Y) / 2}
        class="twofish-round-diagram-value-label"
        text-anchor="start"
        dominant-baseline="middle"
      >
        T0
      </text>
      <line
        x1={RAIL_X[1]}
        y1={G_BOTTOM}
        x2={T1_IN_X}
        y2={PHT_Y}
        class="twofish-round-diagram-wire"
      />
      <text
        x={(RAIL_X[1] + T1_IN_X) / 2 - 4}
        y={(G_BOTTOM + PHT_Y) / 2}
        class="twofish-round-diagram-value-label"
        text-anchor="end"
        dominant-baseline="middle"
      >
        T1
      </text>
      <BoxElement
        cx={PHT_CX}
        y={PHT_Y}
        w={PHT_W}
        h={PHT_H}
        label="PHT +K"
        ids={m().phtIds}
        {...props}
        testid="twofish-round-diagram-pht"
      />

      {/* ─── F0 / F1 out of the PHT: into their own lane, then down clear of
              every chip, entering their target ⊕ from the side. ─── */}
      <For each={[0, 1] as const}>
        {(fIdx) => {
          const target = fTarget(fIdx);
          if (!target) return null;
          const stubX = fIdx === 0 ? F0_X : F1_X;
          const laneY = F_LANE_Y[fIdx];
          const dropX = target.x - F_DROP_INSET;
          return (
            <>
              <polyline
                points={`${stubX},${PHT_BOTTOM} ${stubX},${laneY} ${dropX},${laneY} ${dropX},${target.y} ${target.x - CHIP_W / 2},${target.y}`}
                class="twofish-round-diagram-wire twofish-round-diagram-wire-f"
                fill="none"
              />
              <text
                x={fIdx === 0 ? stubX - 4 : stubX + 4}
                y={PHT_BOTTOM + 10}
                class="twofish-round-diagram-value-label"
                text-anchor={fIdx === 0 ? "end" : "start"}
              >
                F{fIdx}
              </text>
            </>
          );
        }}
      </For>

      {/* ─── The two mix rails: each carried word's rail runs down through its
              ⊕ F and its 1-bit rotation, in spec order. ─── */}
      <For each={railsWithX()}>
        {(entry) => (
          <>
            <line
              x1={entry.x}
              y1={INPUT_BOTTOM}
              x2={entry.x}
              y2={SWAP_TOP}
              class="twofish-round-diagram-wire"
            />
            <For each={entry.rail.nodes}>
              {(node, i) => (
                <ChipElement
                  cx={entry.x}
                  y={mixNodeY(i())}
                  w={CHIP_W}
                  label={node.label}
                  ids={[node.id]}
                  {...props}
                  testid={`twofish-round-diagram-mix-${node.id}`}
                />
              )}
            </For>
          </>
        )}
      </For>

      {/* ─── The swap: four wires from where each value actually is to the slot
              it lands in. Mixed and carried get different strokes so the
              mirror-image diagonals stay tellable apart; every wire terminates
              in a LABELED word, which is what keeps the crossing honest — an
              unlabelled X can't be checked against the bytes. ─── */}
      <For each={[0, 1, 2, 3] as const}>
        {(slot) => (
          <line
            x1={swapOriginX(slot)}
            y1={SWAP_TOP}
            x2={RAIL_X[slot] ?? 0}
            y2={OUT_Y}
            class="twofish-round-diagram-wire"
            classList={{
              "twofish-round-diagram-wire-mix": slot < 2,
              "twofish-round-diagram-wire-pass": slot >= 2,
            }}
          />
        )}
      </For>
      <text
        x={SVG_WIDTH - 6}
        y={(SWAP_TOP + OUT_Y) / 2}
        class="twofish-round-diagram-swap-label"
        text-anchor="end"
      >
        swap
      </text>

      {/* ─── Output words, labeled by what they ARE. No "mixed" accent here:
              the accent means "the active frame is this element" everywhere
              else in the diagram, and the swap wires' own colours already say
              which pair was mixed. ─── */}
      <For each={[0, 1, 2, 3] as const}>
        {(slot) => (
          <WordRect
            cx={RAIL_X[slot] ?? 0}
            y={OUT_Y}
            label={m().outputLabels[slot] ?? ""}
            id={m().recombineId}
            {...props}
            testid={`twofish-round-diagram-output-${slot}`}
          />
        )}
      </For>
    </svg>
  );
};

// ─── Element primitives ───────────────────────────────────────────────────

type ElementCtx = {
  activeLeafId: string;
  frameIndexByLeafId: ReadonlyMap<string, number>;
};

/** Scrub to a leaf's frame if it has one in the active block. */
const scrubTo = (ctx: ElementCtx, id: string): void => {
  const idx = ctx.frameIndexByLeafId.get(id);
  if (idx !== undefined) setFrame(idx);
};

/**
 * An input or output word. Scrubs to the leaf that produced the whole row —
 * the split for the inputs, the recombine for the outputs — so clicking any
 * word lands on the frame where that row's bytes exist.
 */
const WordRect = (
  props: ElementCtx & {
    cx: number;
    y: number;
    label: string;
    /** The leaf this row belongs to (the split, or the recombine). */
    id: string;
    testid: string;
  },
) => {
  const isActive = (): boolean => props.activeLeafId === props.id;
  const isClickable = (): boolean => props.frameIndexByLeafId.has(props.id);
  const handleClick = (): void => scrubTo(props, props.id);
  const handleKey = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleClick();
    }
  };

  return (
    <g
      class="twofish-round-diagram-word-group"
      classList={{
        "twofish-round-diagram-active": isActive(),
        "twofish-round-diagram-clickable": isClickable(),
      }}
      onClick={handleClick}
      onKeyDown={handleKey}
      tabindex={isClickable() ? 0 : undefined}
      data-testid={props.testid}
    >
      <rect
        x={props.cx - WORD_W / 2}
        y={props.y}
        width={WORD_W}
        height={WORD_H}
        class="twofish-round-diagram-word"
        rx="3"
      />
      <text
        x={props.cx}
        y={props.y + WORD_H / 2}
        class="twofish-round-diagram-word-label"
        text-anchor="middle"
        dominant-baseline="middle"
      >
        {props.label}
      </text>
    </g>
  );
};

/**
 * A composite element (a g box, the PHT): one rect standing for several leaves.
 * Accented when the active frame is any of them — the "you are here" cue that
 * makes the diagram useful while scrubbing.
 */
const BoxElement = (
  props: ElementCtx & {
    cx: number;
    y: number;
    w: number;
    h: number;
    label: string;
    ids: readonly string[];
    testid: string;
  },
) => {
  const isActive = (): boolean => props.ids.includes(props.activeLeafId);
  const target = (): string | undefined => props.ids.find((id) => props.frameIndexByLeafId.has(id));
  const handleClick = (): void => {
    const t = target();
    if (t) scrubTo(props, t);
  };
  const handleKey = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleClick();
    }
  };

  return (
    <g
      class="twofish-round-diagram-box-group"
      classList={{
        "twofish-round-diagram-active": isActive(),
        "twofish-round-diagram-clickable": target() !== undefined,
      }}
      onClick={handleClick}
      onKeyDown={handleKey}
      tabindex={target() !== undefined ? 0 : undefined}
      data-testid={props.testid}
    >
      <rect
        x={props.cx - props.w / 2}
        y={props.y}
        width={props.w}
        height={props.h}
        class="twofish-round-diagram-box"
        rx="4"
      >
        <title>{`${props.label} — ${props.ids.length} steps; click to scrub inside`}</title>
      </rect>
      <text
        x={props.cx}
        y={props.y + props.h / 2}
        class="twofish-round-diagram-box-label"
        text-anchor="middle"
        dominant-baseline="middle"
      >
        {props.label}
      </text>
    </g>
  );
};

/** A single-leaf element on a rail (a rotation chip, an `⊕ F` combine). */
const ChipElement = (
  props: ElementCtx & {
    cx: number;
    y: number;
    w: number;
    label: string;
    ids: readonly string[];
    testid: string;
  },
) => {
  const id = (): string => props.ids[0] ?? "";
  const isActive = (): boolean => props.activeLeafId === id();
  const isClickable = (): boolean => props.frameIndexByLeafId.has(id());
  const handleClick = (): void => scrubTo(props, id());
  const handleKey = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleClick();
    }
  };

  return (
    <g
      class="twofish-round-diagram-chip-group"
      classList={{
        "twofish-round-diagram-active": isActive(),
        "twofish-round-diagram-clickable": isClickable(),
      }}
      onClick={handleClick}
      onKeyDown={handleKey}
      tabindex={isClickable() ? 0 : undefined}
      data-testid={props.testid}
    >
      <rect
        x={props.cx - props.w / 2}
        y={props.y}
        width={props.w}
        height={CHIP_H}
        class="twofish-round-diagram-chip"
        rx="3"
      >
        <title>{id()}</title>
      </rect>
      <text
        x={props.cx}
        y={props.y + CHIP_H / 2}
        class="twofish-round-diagram-chip-label"
        text-anchor="middle"
        dominant-baseline="middle"
      >
        {props.label}
      </text>
    </g>
  );
};
