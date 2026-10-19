/**
 * ML-DSA's rounding picture: a value on the bucket ruler, its high and low
 * parts, and how one hint bit moves the verifier into the right bucket.
 *
 * Self-detects an `ml-dsa.decompose@1`, `ml-dsa.make-hint@1` or
 * `ml-dsa.use-hint@1` frame and renders nothing otherwise. The model — which
 * coefficient, which buckets, where each dot sits — is the pure
 * `roundingDiagramModel` in `src/core/ml-dsa-diagram.ts`; this file only draws.
 *
 * **Why these three steps share one picture.** They are one idea told three
 * times. Decompose cuts 0 … q − 1 into m buckets, 2γ2 wide, and keeps only the
 * bucket number (the high bits) in the signature. MakeHint, on the signer's
 * side, asks whether the small difference the verifier will suffer pushes a
 * value across a bucket edge. UseHint, on the verifier's side, moves such a
 * value back — to the neighbour its low part points at. Each is a dot, a
 * bucket, and (for the hints) an arrow over an edge.
 *
 * Layout, top to bottom:
 *
 * ```
 *   ▭▭▭▭▭▭▭▭▭▭█▭▭▭▭▭ … ▭   every bucket on the circle, the close-up's marked
 *         ╭─ hint ─╮          UseHint only: home bucket → corrected bucket
 *   ┌──────┬──────┬──────┐
 *   │ k−1  │  k   │ k+1  │    the close-up: the value's bucket and neighbours
 *   │      │  ●──►●      │    MakeHint: r → r + z across an edge
 *   │      │ ├──┤ │      │    Decompose / UseHint: the low part, centre → dot
 *   └──────┴──┴───┴──────┘
 *             centre value
 * ```
 *
 * Dots are placed by their LOW PART from their own bucket's centre, never by
 * raw value — see the model's rule 1; a wrapped value would otherwise land
 * outside its box.
 */

import {
  type CloseUpPoint,
  type RoundingDiagramModel,
  roundingDiagramModel,
} from "@/core/ml-dsa-diagram";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { num } from "../narration/lattice";

type Props = {
  frame: TraceFrame;
};

// ─── geometry (SVG units) ─────────────────────────────────────────────────

const W = 600;
const LEFT = 20;
const RIGHT = W - 20;
const STRIP_Y = 6;
const STRIP_H = 10;
const BOX_TOP = 56;
const BOX_BOTTOM = 124;
const LABEL_Y = 70;
const VALUE_LABEL_Y = 86;
const DOT_Y = 96;
const BRACKET_Y = 106;
const BRACKET_LABEL_Y = 118;
const SECOND_LABEL_Y = 112;
const TICK_BOTTOM = 130;
const CENTRE_LABEL_Y = 142;
const H = 150;

/** `−5` with a real minus sign, thousands separated; `+5` when asked. */
const sNum = (v: number, plus = false): string =>
  v < 0 ? `−${num(-v)}` : `${plus && v > 0 ? "+" : ""}${num(v)}`;

/**
 * Where a value's label goes: inside the value's OWN bucket, running away from
 * the nearer edge. Hinted values sit a hair from an edge by construction, and a
 * label centred on the dot had the edge line running through its digits (found
 * by looking — no unit test sees it). A bucket is ~187 units wide at this
 * scale, so a label reaching inward from either edge always fits.
 */
const inward = (
  pt: CloseUpPoint,
  gamma2: number,
): { dx: number; anchor: "start" | "middle" | "end" } => {
  const o = pt.placement.offset;
  if (Math.abs(o) < gamma2 / 3) return { dx: 0, anchor: "middle" };
  return o > 0 ? { dx: -7, anchor: "end" } : { dx: 7, anchor: "start" };
};

const STEP_NAME: Record<RoundingDiagramModel["kind"], string> = {
  decompose: "Decompose",
  "make-hint": "MakeHint",
  "use-hint": "UseHint",
};

export const MlDsaRoundingDiagram = (props: Props) => {
  const model = createMemo<RoundingDiagramModel | null>(() => roundingDiagramModel(props.frame));

  return (
    <Show when={model()}>
      {(getModel) => {
        // The close-up spans three buckets: 6γ2 across the drawing width.
        const xOf = (offset: number): number =>
          (LEFT + RIGHT) / 2 + (offset * (RIGHT - LEFT)) / (6 * getModel().gamma2);
        const cellW = (): number => (RIGHT - LEFT) / getModel().m;
        const primary = (): CloseUpPoint => getModel().points[0] as CloseUpPoint;
        const second = (): CloseUpPoint | undefined => getModel().points[1];
        const targetSlot = (): number | undefined =>
          getModel().buckets.find((b) => b.index === getModel().target)?.slot;
        const showsLowPart = (): boolean => getModel().kind !== "make-hint";

        return (
          <section class="ml-dsa-rounding-diagram" aria-label="rounding to buckets diagram">
            <div class="ml-dsa-rounding-diagram-header">
              <span class="ml-dsa-rounding-diagram-title">rounding to buckets</span>
              <code class="ml-dsa-rounding-diagram-kind">
                {`${STEP_NAME[getModel().kind]} · ${getModel().m} buckets, each 2γ2 = ${num(
                  2 * getModel().gamma2,
                )} wide · coefficient ${getModel().coefficient} of ${num(getModel().count)}`}
              </code>
            </div>

            <svg
              class="ml-dsa-rounding-diagram-svg"
              viewBox={`0 0 ${W} ${H}`}
              width={W}
              height={H}
              role="img"
              aria-label={`coefficient ${getModel().coefficient} in bucket ${getModel().home} of ${getModel().m}`}
            >
              <defs>
                <marker
                  id="ml-dsa-rounding-arrow"
                  viewBox="0 0 10 10"
                  refX="9"
                  refY="5"
                  markerWidth="7"
                  markerHeight="7"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" class="ml-dsa-rounding-diagram-arrowhead" />
                </marker>
              </defs>

              {/* Every bucket on the circle, so the close-up has a place. */}
              <For each={Array.from({ length: getModel().m }, (_, k) => k)}>
                {(k) => (
                  <rect
                    x={LEFT + k * cellW()}
                    y={STRIP_Y}
                    width={Math.max(cellW() - 1, 1)}
                    height={STRIP_H}
                    class={
                      k === getModel().home
                        ? "ml-dsa-rounding-diagram-cell ml-dsa-rounding-diagram-cell-home"
                        : k === getModel().target
                          ? "ml-dsa-rounding-diagram-cell ml-dsa-rounding-diagram-cell-target"
                          : "ml-dsa-rounding-diagram-cell"
                    }
                  />
                )}
              </For>
              <text x={LEFT} y={STRIP_Y + STRIP_H + 11} class="ml-dsa-rounding-diagram-small">
                0
              </text>
              <text
                x={RIGHT}
                y={STRIP_Y + STRIP_H + 11}
                text-anchor="end"
                class="ml-dsa-rounding-diagram-small"
              >
                {`q − 1 = ${num(getModel().q - 1)}`}
              </text>

              {/* The close-up: the value's own bucket and its two neighbours. */}
              <For each={getModel().buckets}>
                {(b) => (
                  <g>
                    <rect
                      x={xOf(b.slot * 2 * getModel().gamma2 - getModel().gamma2)}
                      y={BOX_TOP}
                      width={xOf(getModel().gamma2) - xOf(-getModel().gamma2)}
                      height={BOX_BOTTOM - BOX_TOP}
                      class={
                        b.slot === 0
                          ? "ml-dsa-rounding-diagram-bucket ml-dsa-rounding-diagram-bucket-home"
                          : b.index === getModel().target
                            ? "ml-dsa-rounding-diagram-bucket ml-dsa-rounding-diagram-bucket-target"
                            : "ml-dsa-rounding-diagram-bucket"
                      }
                    />
                    <text
                      x={xOf(b.slot * 2 * getModel().gamma2)}
                      y={LABEL_Y}
                      class="ml-dsa-rounding-diagram-bucket-label"
                    >
                      {`bucket ${b.index}`}
                    </text>
                    <line
                      x1={xOf(b.slot * 2 * getModel().gamma2)}
                      x2={xOf(b.slot * 2 * getModel().gamma2)}
                      y1={BOX_BOTTOM - 6}
                      y2={TICK_BOTTOM}
                      class="ml-dsa-rounding-diagram-tick"
                    />
                    <text
                      x={xOf(b.slot * 2 * getModel().gamma2)}
                      y={CENTRE_LABEL_Y}
                      class="ml-dsa-rounding-diagram-centre-label"
                    >
                      {`centre ${num(b.centreValue)}`}
                    </text>
                  </g>
                )}
              </For>

              {/* UseHint: the step's corrected bucket, as an arc over the edge. */}
              <Show
                when={
                  getModel().kind === "use-hint" && targetSlot() !== undefined && targetSlot() !== 0
                }
              >
                <path
                  d={`M ${xOf(0)} ${BOX_TOP} Q ${(xOf(0) + xOf((targetSlot() ?? 0) * 2 * getModel().gamma2)) / 2} ${BOX_TOP - 30} ${xOf((targetSlot() ?? 0) * 2 * getModel().gamma2)} ${BOX_TOP}`}
                  class="ml-dsa-rounding-diagram-hop"
                  marker-end="url(#ml-dsa-rounding-arrow)"
                />
                <text
                  x={(xOf(0) + xOf((targetSlot() ?? 0) * 2 * getModel().gamma2)) / 2}
                  y={BOX_TOP - 20}
                  class="ml-dsa-rounding-diagram-hop-label"
                >
                  {`hint 1 → bucket ${getModel().target}`}
                </text>
              </Show>

              {/* The low part: from the bucket's centre to the value. */}
              <Show when={showsLowPart()}>
                <line
                  x1={xOf(0)}
                  x2={xOf(primary().x)}
                  y1={BRACKET_Y}
                  y2={BRACKET_Y}
                  class="ml-dsa-rounding-diagram-bracket"
                />
                <line
                  x1={xOf(0)}
                  x2={xOf(0)}
                  y1={BRACKET_Y - 3}
                  y2={BRACKET_Y + 3}
                  class="ml-dsa-rounding-diagram-bracket"
                />
                <line
                  x1={xOf(primary().x)}
                  x2={xOf(primary().x)}
                  y1={BRACKET_Y - 3}
                  y2={BRACKET_Y + 3}
                  class="ml-dsa-rounding-diagram-bracket"
                />
                <text
                  x={(xOf(0) + xOf(primary().x)) / 2}
                  y={BRACKET_LABEL_Y}
                  class="ml-dsa-rounding-diagram-bracket-label"
                >
                  {`low part ${sNum(primary().placement.offset, true)}`}
                </text>
              </Show>

              {/* MakeHint: r → r + z. The arrow crosses an edge iff the hint is 1. */}
              <Show when={second()}>
                {(getSecond) => (
                  <>
                    {/* An arc, not a line: a hinted shift is often only a
                        few pixels wide (tiny next to a bucket), and a
                        straight arrow vanished between the two dots. */}
                    <Show when={getSecond().x !== primary().x}>
                      <path
                        d={`M ${xOf(primary().x)} ${DOT_Y - 5} Q ${(xOf(primary().x) + xOf(getSecond().x)) / 2} ${DOT_Y - 24} ${xOf(getSecond().x)} ${DOT_Y - 6}`}
                        class="ml-dsa-rounding-diagram-shift"
                        marker-end="url(#ml-dsa-rounding-arrow)"
                      />
                    </Show>
                    <circle
                      cx={xOf(getSecond().x)}
                      cy={DOT_Y}
                      r={4}
                      class="ml-dsa-rounding-diagram-dot ml-dsa-rounding-diagram-dot-second"
                    />
                    <text
                      x={xOf(getSecond().x) + inward(getSecond(), getModel().gamma2).dx}
                      y={SECOND_LABEL_Y}
                      text-anchor={inward(getSecond(), getModel().gamma2).anchor}
                      class="ml-dsa-rounding-diagram-value-label"
                    >
                      {`${getSecond().label} = ${num(getSecond().value)}`}
                    </text>
                  </>
                )}
              </Show>

              <circle cx={xOf(primary().x)} cy={DOT_Y} r={4} class="ml-dsa-rounding-diagram-dot" />
              <text
                x={xOf(primary().x) + inward(primary(), getModel().gamma2).dx}
                y={VALUE_LABEL_Y}
                text-anchor={inward(primary(), getModel().gamma2).anchor}
                class="ml-dsa-rounding-diagram-value-label"
              >
                {`${primary().label} = ${num(primary().value)}`}
              </text>
            </svg>

            <p class="ml-dsa-rounding-diagram-note muted small">
              <Caption model={getModel()} />
            </p>
          </section>
        );
      }}
    </Show>
  );
};

/** MakeHint: the signed shift z, as drawn (r + z's position minus r's). */
const shift = (m: RoundingDiagramModel): number => (m.points[1]?.x ?? 0) - (m.points[0]?.x ?? 0);

/** Does the shift carry r up (into the next bucket) rather than down? */
const movesUp = (m: RoundingDiagramModel): boolean => shift(m) > 0;

/** How far r sits from the edge the shift crosses. */
const edgeGap = (m: RoundingDiagramModel): number => {
  const o = m.points[0]?.placement.offset ?? 0;
  return movesUp(m) ? m.gamma2 - o : o + m.gamma2;
};

/** The sentence under the picture — what this frame's coefficient shows. */
const Caption = (props: { model: RoundingDiagramModel }) => {
  const m = () => props.model;
  const p = () => m().points[0] as CloseUpPoint;
  return (
    <>
      <Show when={m().kind === "decompose"}>
        Coefficient {m().coefficient} is {num(p().value)}: bucket {m().home}, whose centre is{" "}
        {num(m().home * 2 * m().gamma2)}, and {sNum(p().placement.offset, true)} from that centre.
        Decompose keeps the bucket number as the high bits — the part a signature commits to — and
        the offset as the low bits, which it drops.
        <Show when={p().placement.wrapped}>
          {" "}
          This value is within γ2 of q − 1, just below zero on the circle, so it goes in bucket 0
          with a negative offset: there is no bucket {m().m}.
        </Show>
      </Show>
      <Show when={m().kind === "make-hint"}>
        <Show
          when={m().hint === 1}
          fallback={
            <>
              No coefficient on this frame changes bucket, so every hint bit is 0. Coefficient 0 is
              shown.
            </>
          }
        >
          Coefficient {m().coefficient}: r is in bucket {m().home}, only {num(edgeGap(m()))} from
          its {movesUp(m()) ? "upper" : "lower"} edge, and z = {sNum(shift(m()), true)} carries it
          into bucket {m().target}, so its hint bit is 1. The shift is tiny next to a bucket{" "}
          {num(2 * m().gamma2)} wide; it matters only because r sat so close to the edge.
        </Show>{" "}
        In signing, r is the value the verifier will compute and r + z the value the signer
        committed to; the two differ by the small c·t0 the verifier never sees. A hint marks each
        coefficient where that difference crosses a bucket edge — {num(m().hintedCount ?? 0)} of{" "}
        {num(m().count)} here. A signature has room for at most ω of them.
      </Show>
      <Show when={m().kind === "use-hint"}>
        <Show
          when={m().hint === 1}
          fallback={
            <>
              No coefficient on this frame carries a hint, so every value keeps its bucket.
              Coefficient 0 is shown.
            </>
          }
        >
          The verifier has only r = {num(p().value)}, in bucket {m().home} at offset{" "}
          {sNum(p().placement.offset, true)}, and a hint bit of 1. The hint says the signer's value
          was in a neighbouring bucket; the offset is{" "}
          {p().placement.offset > 0 ? "positive (the upper half)" : "not positive (the lower half)"}
          , so it is the bucket {p().placement.offset > 0 ? "above" : "below"}: {m().target}.
        </Show>{" "}
        The signer's value itself is not on this frame — only the hint bit carries it. Buckets wrap:
        one below 0 is {m().m - 1}, and one above {m().m - 1} is 0.
      </Show>
    </>
  );
};
