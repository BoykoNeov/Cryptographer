/**
 * ChaCha20 quarter-round diagram — the linear view's *abstract* picture of one
 * quarter round, and the ARX sibling of `TwofishRoundDiagram`.
 *
 * ChaCha20 is neither a 2-way Feistel nor Twofish's 4-rail form, so both
 * existing analyzers return null for it and the whole linear diagram surface
 * stays dark. This component fills that gap: it self-detects a port-native
 * ChaCha quarter round from the double round's wiring (`core/chacha-shape.ts`)
 * and renders nothing otherwise, so it is inert for every other cipher.
 *
 * **What it teaches, and why the linear view is where it belongs.** A ChaCha
 * double round is 98 leaves; the graph view's canonical cell arranges them into
 * eight blocks of four lines, which is the right picture at THAT altitude — it
 * shows you the double round's anatomy. What it cannot show is the thing that
 * makes a quarter round work: that these twelve operations are four *rails*
 * being alternately added, XORed and rotated into each other, and that a change
 * to any one word reaches all four. Drawn as rails, that is immediate:
 *
 * ```
 *   a ──●──────────────────[+b]──────────────  a += b;  a += b
 *   b ──│──[⊕c]──[<<<12]────│───[⊕c]──[<<<7]─  b ^= c;  b <<<= 12; …
 *   c ──│───●─────[+d]──────│────●─────[+d]──  c += d
 *   d ──[⊕a]──[<<<16]───────[⊕a]──[<<<8]─────  d ^= a;  d <<<= 16; …
 * ```
 *
 * The four RFC lines are banded so the `+ / ⊕ / <<<` triple reads as one unit,
 * which is the cipher's actual rhythm: add mixes with carries, XOR mixes
 * without, and the rotation moves high bits down where the next addition's
 * carries can reach them.
 *
 * **Every label is derived from wiring** (`core/chacha-diagram.ts`) — including
 * the state-word indices that let the header name this quarter round the way
 * RFC 8439 §2.3.1 names it, `QUARTERROUND(0, 5, 10, 15)`. That is the one fact
 * distinguishing eight otherwise-identical quarter rounds, and it is the reason
 * this diagram is worth drawing at all rather than printing the RFC's text.
 *
 * ChaCha20's encrypt and decrypt specs are structurally identical, so unlike
 * the Twofish diagram this one needs no direction-awareness anywhere.
 *
 * Interaction mirrors the other two diagrams: the element containing the active
 * leaf is accented ("you are here"), and clicking an element scrubs the trace to
 * its frame. Here every element IS a single leaf — there are no composites — so
 * every box scrubs exactly.
 */

import { type ChaChaDiagramModel, chachaDiagramModel } from "@/core/chacha-diagram";
import { findActiveChaChaQuarterRound } from "@/core/chacha-shape";
import { canonicalStepId } from "@/core/step-id";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";

type Props = {
  frame: TraceFrame;
};

const EMPTY_INDEX_MAP: ReadonlyMap<string, number> = new Map();

export const ChaChaQuarterRoundDiagram = (props: Props) => {
  const spec = useSpec();
  const version = useTraceVersion();

  const model = createMemo<ChaChaDiagramModel | null>(() => {
    const active = findActiveChaChaQuarterRound(props.frame, spec());
    if (!active) return null;
    return chachaDiagramModel(active.round, active.quarterRoundIndex);
  });

  // Frame index per leaf in the ACTIVE block — drives click-to-scrub. Recomputes
  // on each Run (trace-version) and when the quarter round changes. The
  // block-index match keeps a multi-block trace scrubbing within the block the
  // user is looking at, exactly as the Feistel and Twofish diagrams do.
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
        <section class="chacha-qr-diagram" aria-label="chacha20 quarter round diagram">
          <div class="chacha-qr-diagram-header">
            <span class="chacha-qr-diagram-title">chacha20 quarter round</span>
            <code class="chacha-qr-diagram-kind">
              {getModel().rfcLabel ?? `${getModel().kind} round`}
            </code>
          </div>
          <DiagramSvg
            model={getModel()}
            activeLeafId={canonicalStepId(props.frame.stepId)}
            frameIndexByLeafId={frameIndexByLeafId()}
          />
          <p class="chacha-qr-diagram-note muted small">
            Four words, twelve operations, three kinds: <strong>add</strong> mixes with carries,{" "}
            <strong>XOR</strong> mixes without, and the <strong>rotation</strong> moves high bits
            back down so the next addition's carries reach them. This is a{" "}
            <strong>{getModel().kind}</strong> round — one of the eight that make up a double round,
            and the {getModel().kind === "column" ? "columns" : "diagonals"} of the 4×4 state are
            what it mixes.
          </p>
        </section>
      )}
    </Show>
  );
};

// ─── SVG geometry ─────────────────────────────────────────────────────────
// Four horizontal rails (a, b, c, d top to bottom) crossed by twelve stations,
// one per operation, left to right in RFC 8439 §2.1 order.
//
// The routing rule that matters is the same one the Twofish diagram learned by
// LOOKING: a wire may cross another wire, but must never pass through a
// labelled box. Here that is satisfied by construction — each station owns its
// own x, and only the station's TARGET rail carries a box at that x, so an
// operand connector (which runs vertically at exactly that x) crosses only bare
// rail lines on its way. `d ^= a` spans three rails and is the long one; it
// still touches no box but its own.

const RAIL_Y = [46, 84, 122, 160] as const;
const RAIL_LABEL_X = 10;
const RAIL_START_X = 62;

const STATION_X0 = 92;
const STATION_PITCH = 43;

const OP_W = 36;
const OP_H = 20;

/** Operations per RFC line — the banding unit. */
const OPS_PER_LINE = 3;

const SVG_WIDTH = STATION_X0 + 11 * STATION_PITCH + OP_W / 2 + 58;
const SVG_HEIGHT = 196;
const RAIL_END_X = SVG_WIDTH - 46;

/** Band geometry for one RFC line (a group of three stations). */
const BAND_TOP = 24;
const BAND_BOTTOM = 180;

const stationX = (i: number): number => STATION_X0 + i * STATION_PITCH;
const railY = (rail: string): number => RAIL_Y[["a", "b", "c", "d"].indexOf(rail)] ?? RAIL_Y[0];

const DiagramSvg = (props: {
  model: ChaChaDiagramModel;
  activeLeafId: string;
  frameIndexByLeafId: ReadonlyMap<string, number>;
}) => {
  const m = (): ChaChaDiagramModel => props.model;

  return (
    <svg
      class="chacha-qr-diagram-svg"
      width={SVG_WIDTH}
      height={SVG_HEIGHT}
      viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
      role="img"
      aria-label="chacha20 quarter round: four rails crossed by twelve add, xor and rotate operations"
    >
      {/* ─── Bands: one per RFC line, so each +/⊕/<<< triple reads as a unit ─── */}
      <For each={[0, 1, 2, 3]}>
        {(line) => (
          <rect
            x={stationX(line * OPS_PER_LINE) - OP_W / 2 - 7}
            y={BAND_TOP}
            width={(OPS_PER_LINE - 1) * STATION_PITCH + OP_W + 14}
            height={BAND_BOTTOM - BAND_TOP}
            class={
              line % 2 === 0
                ? "chacha-qr-diagram-band"
                : "chacha-qr-diagram-band chacha-qr-diagram-band-alt"
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
              class="chacha-qr-diagram-rail"
            />
            <text
              x={RAIL_LABEL_X}
              y={railY(rail.rail) + 4}
              class="chacha-qr-diagram-rail-label"
              data-testid={`chacha-qr-rail-${rail.rail}`}
            >
              {rail.rail}
              {rail.wordIndex === null ? "" : ` (w${rail.wordIndex})`}
            </text>
          </>
        )}
      </For>

      {/* ─── The twelve operations ─── */}
      <For each={m().ops}>
        {(op, i) => {
          const x = stationX(i());
          const ty = railY(op.target);
          const frameIndex = (): number | undefined => props.frameIndexByLeafId.get(op.nodeId);
          const short =
            op.kind === "add"
              ? `+${op.source}`
              : op.kind === "xor"
                ? `⊕${op.source}`
                : `≪${op.bits}`;
          const scrub = (): void => {
            const idx = frameIndex();
            if (idx !== undefined) setFrame(idx);
          };
          // Keyboard parity with the Twofish diagram: an operation reachable by
          // click must be reachable by Tab + Enter/Space too.
          const onKey = (e: KeyboardEvent): void => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              scrub();
            }
          };
          return (
            <g
              class={`chacha-qr-diagram-op${
                props.activeLeafId === op.nodeId ? " chacha-qr-diagram-active" : ""
              }${frameIndex() === undefined ? "" : " chacha-qr-diagram-clickable"}`}
              onClick={scrub}
              onKeyDown={onKey}
              tabindex={frameIndex() === undefined ? undefined : 0}
              data-testid={`chacha-qr-op-${i()}`}
            >
              <title>{op.label}</title>
              {/* Operand connector: from the source rail down/up to this box.
                  Rotations have no operand, so they draw none. */}
              <Show when={op.kind !== "rotate"}>
                <line
                  x1={x}
                  y1={railY((op as { source: string }).source)}
                  x2={x}
                  y2={ty}
                  class="chacha-qr-diagram-operand"
                />
                <circle
                  cx={x}
                  cy={railY((op as { source: string }).source)}
                  r={2.5}
                  class="chacha-qr-diagram-tap"
                />
              </Show>
              <rect
                x={x - OP_W / 2}
                y={ty - OP_H / 2}
                width={OP_W}
                height={OP_H}
                rx={3}
                class={`chacha-qr-diagram-box chacha-qr-diagram-box-${op.kind}`}
              />
              <text x={x} y={ty + 4} class="chacha-qr-diagram-box-label">
                {short}
              </text>
            </g>
          );
        }}
      </For>
    </svg>
  );
};
