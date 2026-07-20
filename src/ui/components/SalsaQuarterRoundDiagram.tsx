/**
 * Salsa20 quarter-round diagram — the linear view's *abstract* picture of one
 * quarter round, and the fourth member of the abstract-diagram family
 * (`FeistelSwapDiagram`, `TwofishRoundDiagram`, `ChaChaQuarterRoundDiagram`).
 *
 * It self-detects a port-native Salsa quarter round from the double round's
 * wiring (`core/salsa-shape.ts`) and renders nothing otherwise, so it is inert
 * for every other cipher — including ChaCha20, whose analyzer and this one
 * mutually decline each other's rounds.
 *
 * **What it teaches, and why it is NOT ChaCha's diagram with different labels.**
 * ChaCha accumulates in place, so all twelve of its operations sit on one of the
 * four rails and the picture is four rails crossed by twelve boxes. Salsa
 * computes into a FRESH rail:
 *
 * ```
 *   z1 = y1 ^ ((y0 + y3) <<<  7)
 *   z2 = y2 ^ ((z1 + y0) <<<  9)
 *   z3 = y3 ^ ((z2 + z1) <<< 13)
 *   z0 = y0 ^ ((z3 + z2) <<< 18)
 * ```
 *
 * so of each line's three operations the add and the rotate touch **no state
 * word at all**. Drawing them on a rail would be a lie about the dataflow. They
 * are drawn instead on a per-line SCRATCH LANE below the rails: two operands
 * drop down out of their rails into the add, the sum travels right through the
 * rotate, and only then does it climb back up into the XOR on the target rail.
 * That descent-and-return is the shape of the cipher, and it is the one thing a
 * reader should take away from this diagram that ChaCha's does not show.
 *
 * A fresh scratch segment is drawn per line rather than one continuous lane,
 * because the scratch value genuinely does not survive its line.
 *
 * **Every label is derived from wiring** (`core/salsa-diagram.ts`) — including
 * the state-word indices that let the header name this quarter round as
 * `quarterround(x5, x9, x13, x1)`. That quad is printed in rail order and never
 * sorted: a Salsa column quarter round STARTS ON THE DIAGONAL, which is the
 * whole reason the state is laid out the way it is, and sorting the label would
 * silently erase it.
 *
 * Salsa20's encrypt and decrypt specs are structurally identical, so like the
 * ChaCha diagram this one needs no direction-awareness anywhere.
 *
 * Interaction mirrors the other three diagrams: the element containing the
 * active leaf is accented ("you are here"), and clicking an element scrubs the
 * trace to its frame. Every element IS a single leaf — there are no composites —
 * so every box scrubs exactly.
 */

import { type SalsaDiagramModel, salsaDiagramModel } from "@/core/salsa-diagram";
import { findActiveSalsaQuarterRound } from "@/core/salsa-shape";
import { canonicalStepId } from "@/core/step-id";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";

type Props = {
  frame: TraceFrame;
};

const EMPTY_INDEX_MAP: ReadonlyMap<string, number> = new Map();

export const SalsaQuarterRoundDiagram = (props: Props) => {
  const spec = useSpec();
  const version = useTraceVersion();

  const model = createMemo<SalsaDiagramModel | null>(() => {
    const active = findActiveSalsaQuarterRound(props.frame, spec());
    if (!active) return null;
    return salsaDiagramModel(active.round, active.quarterRoundIndex);
  });

  // Frame index per leaf in the ACTIVE quarter round — drives click-to-scrub.
  // Recomputes on each Run (trace-version) and when the quarter round changes.
  // The block-index match keeps a multi-block trace scrubbing within the block
  // the user is looking at, exactly as the other three diagrams do.
  const frameIndexByLeafId = createMemo<ReadonlyMap<string, number>>(() => {
    void version();
    const m = model();
    if (!m) return EMPTY_INDEX_MAP;
    const t = getTrace();
    if (!t) return EMPTY_INDEX_MAP;
    const blockIdx = props.frame.blockIndex;
    const wanted = new Set(m.ops.map((o) => o.nodeId));
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
        <section class="salsa-qr-diagram" aria-label="salsa20 quarter round diagram">
          <div class="salsa-qr-diagram-header">
            <span class="salsa-qr-diagram-title">salsa20 quarter round</span>
            <code class="salsa-qr-diagram-kind">
              {getModel().quadLabel ?? `${getModel().kind} round`}
            </code>
          </div>
          <DiagramSvg
            model={getModel()}
            activeLeafId={canonicalStepId(props.frame.stepId)}
            frameIndexByLeafId={frameIndexByLeafId()}
          />
          <p class="salsa-qr-diagram-note muted small">
            Four words, twelve operations, three kinds — <strong>add</strong>,{" "}
            <strong>rotate</strong>, <strong>XOR</strong>. Each line adds two words, rotates the
            sum, and XORs the result into a <em>third</em> word: the add and the rotate happen on a
            scratch value that is not yet part of the state, which is why they hang below the rails.
            Only the XOR writes back. This is a <strong>{getModel().kind}</strong> round — one of
            the eight that make up a double round, and the{" "}
            {getModel().kind === "column" ? "columns" : "rows"} of the 4×4 state are what it mixes.
          </p>
        </section>
      )}
    </Show>
  );
};

// ─── SVG geometry ─────────────────────────────────────────────────────────
// Four horizontal rails (y0..y3, top to bottom) plus a per-line SCRATCH lane
// below them, crossed by twelve stations — one per operation, left to right in
// Bernstein's written order.
//
// The routing rule is the same one the Twofish diagram learned by LOOKING: a
// wire may cross another wire, but must never pass through a labelled box. It
// is satisfied by construction here. Each station owns its own x; at that x the
// only box is the station's own (on the scratch lane for an add/rotate, on the
// target rail for an XOR), so a connector running vertically at that x crosses
// bare rail lines only. The add's two operand connectors are nudged apart by
// OPERAND_DX so they enter the box as two visibly distinct wires rather than
// overprinting each other.

const RAIL_Y = [42, 72, 102, 132] as const;
const SCRATCH_Y = 176;
const RAIL_LABEL_X = 10;
const RAIL_START_X = 66;

const STATION_X0 = 100;
const STATION_PITCH = 54;

const OP_W = 46;
const OP_H = 20;

/** Horizontal nudge separating the add's two operand connectors. */
const OPERAND_DX = 9;

/** Operations per written line — the banding unit. */
const OPS_PER_LINE = 3;

const SVG_WIDTH = STATION_X0 + 11 * STATION_PITCH + OP_W / 2 + 40;
const SVG_HEIGHT = 208;
const RAIL_END_X = SVG_WIDTH - 30;

/** Band geometry for one written line (a group of three stations). */
const BAND_TOP = 24;
const BAND_BOTTOM = 194;

const stationX = (i: number): number => STATION_X0 + i * STATION_PITCH;
const railY = (rail: string): number => RAIL_Y[["a", "b", "c", "d"].indexOf(rail)] ?? RAIL_Y[0];

/** The y a given op's box sits at — its rail, or the scratch lane. */
const laneY = (op: { readonly lane: { readonly kind: string; readonly rail?: string } }): number =>
  op.lane.kind === "scratch" ? SCRATCH_Y : railY(op.lane.rail ?? "a");

const DiagramSvg = (props: {
  model: SalsaDiagramModel;
  activeLeafId: string;
  frameIndexByLeafId: ReadonlyMap<string, number>;
}) => {
  const m = (): SalsaDiagramModel => props.model;

  return (
    <svg
      class="salsa-qr-diagram-svg"
      width={SVG_WIDTH}
      height={SVG_HEIGHT}
      viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
      role="img"
      aria-label="salsa20 quarter round: four rails over a scratch lane, crossed by twelve add, rotate and xor operations"
    >
      {/* ─── Bands: one per written line, so each add/rotate/XOR triple reads
              as one expression ─── */}
      <For each={[0, 1, 2, 3]}>
        {(line) => (
          <rect
            x={stationX(line * OPS_PER_LINE) - OP_W / 2 - 8}
            y={BAND_TOP}
            width={(OPS_PER_LINE - 1) * STATION_PITCH + OP_W + 16}
            height={BAND_BOTTOM - BAND_TOP}
            class={
              line % 2 === 0
                ? "salsa-qr-diagram-band"
                : "salsa-qr-diagram-band salsa-qr-diagram-band-alt"
            }
            rx={3}
          />
        )}
      </For>

      {/* ─── The four rails, with their state-word labels ─── */}
      <For each={m().rails}>
        {(rail) => (
          <>
            <line
              x1={RAIL_START_X}
              y1={railY(rail.rail)}
              x2={RAIL_END_X}
              y2={railY(rail.rail)}
              class="salsa-qr-diagram-rail"
            />
            <text
              x={RAIL_LABEL_X}
              y={railY(rail.rail) + 4}
              class="salsa-qr-diagram-rail-label"
              data-testid={`salsa-qr-rail-${rail.rail}`}
            >
              {rail.name}
              {rail.wordIndex === null ? "" : ` (x${rail.wordIndex})`}
            </text>
          </>
        )}
      </For>

      {/* ─── The scratch lane: one segment per line, spanning that line's three
              stations. Drawn per line rather than continuously because the
              value genuinely does not survive past its own XOR. ─── */}
      <For each={[0, 1, 2, 3]}>
        {(line) => (
          <line
            x1={stationX(line * OPS_PER_LINE) - OP_W / 2}
            y1={SCRATCH_Y}
            x2={stationX(line * OPS_PER_LINE + 2)}
            y2={SCRATCH_Y}
            class="salsa-qr-diagram-scratch"
          />
        )}
      </For>
      <text x={RAIL_LABEL_X} y={SCRATCH_Y + 4} class="salsa-qr-diagram-scratch-label">
        (sum)
      </text>

      {/* ─── The twelve operations ─── */}
      <For each={m().ops}>
        {(op, i) => {
          const x = stationX(i());
          const ty = laneY(op);
          const frameIndex = (): number | undefined => props.frameIndexByLeafId.get(op.nodeId);
          const scrub = (): void => {
            const idx = frameIndex();
            if (idx !== undefined) setFrame(idx);
          };
          // Keyboard parity with the other diagrams: an operation reachable by
          // click must be reachable by Tab + Enter/Space too.
          const onKey = (e: KeyboardEvent): void => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              scrub();
            }
          };
          return (
            <g
              class={`salsa-qr-diagram-op${
                props.activeLeafId === op.nodeId ? " salsa-qr-diagram-active" : ""
              }${frameIndex() === undefined ? "" : " salsa-qr-diagram-clickable"}`}
              onClick={scrub}
              onKeyDown={onKey}
              tabindex={frameIndex() === undefined ? undefined : 0}
              data-testid={`salsa-qr-op-${i()}`}
            >
              <title>{op.label}</title>

              {/* An add pulls its two operands DOWN out of their rails into the
                  scratch lane — the descent that makes the fresh rail visible. */}
              <Show when={op.kind === "add"}>
                <For each={op.kind === "add" ? [op.srcA, op.srcB] : []}>
                  {(src, k) => (
                    <>
                      <line
                        x1={x + (k() === 0 ? -OPERAND_DX : OPERAND_DX)}
                        y1={railY(src)}
                        x2={x + (k() === 0 ? -OPERAND_DX : OPERAND_DX)}
                        y2={SCRATCH_Y}
                        class="salsa-qr-diagram-operand"
                      />
                      <circle
                        cx={x + (k() === 0 ? -OPERAND_DX : OPERAND_DX)}
                        cy={railY(src)}
                        r={2.5}
                        class="salsa-qr-diagram-tap"
                      />
                    </>
                  )}
                </For>
              </Show>

              {/* The XOR is the return trip: the rotated sum climbs from the
                  scratch lane back up into its target rail. */}
              <Show when={op.kind === "xor"}>
                <line x1={x} y1={SCRATCH_Y} x2={x} y2={ty} class="salsa-qr-diagram-operand" />
                <circle cx={x} cy={SCRATCH_Y} r={2.5} class="salsa-qr-diagram-tap" />
              </Show>

              <rect
                x={x - OP_W / 2}
                y={ty - OP_H / 2}
                width={OP_W}
                height={OP_H}
                rx={3}
                class={`salsa-qr-diagram-box salsa-qr-diagram-box-${op.kind}`}
              />
              <text x={x} y={ty + 4} class="salsa-qr-diagram-box-label">
                {op.short}
              </text>
            </g>
          );
        }}
      </For>
    </svg>
  );
};
