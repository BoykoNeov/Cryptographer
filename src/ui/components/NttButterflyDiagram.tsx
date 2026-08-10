/**
 * NTT butterfly diagram — the linear view's *abstract* picture of one butterfly,
 * and the lattice sibling of `TwofishRoundDiagram` / `ChaChaQuarterRoundDiagram`
 * / `SalsaQuarterRoundDiagram`.
 *
 * Self-detects a butterfly from the active frame's containing iterate
 * (`core/ntt-shape.ts`) and renders nothing otherwise, so it is inert for every
 * cipher, hash and generator in the app.
 *
 * **What it teaches, and why the linear view is where it belongs.** The graph's
 * canonical cell shows a layer's ANATOMY: eight leaves, two rails, a side lane
 * for the ζ table. What it cannot show is the thing that makes the transform a
 * transform — that two values go in, two come out, and *each output depends on
 * both inputs*. Drawn as two rails and one crossing, that is immediate:
 *
 * ```
 *   lo ─────────────●───── lo + t          lo ────●──────────────── lo + hi
 *                  ╱ ╲                             ╲╱
 *   hi ──[× ζ]─────●───── lo − t          hi ─────╱╲───[× ζ]─────── ζ(hi − lo)
 *
 *      Cooley–Tukey (forward)               Gentleman–Sande (inverse)
 * ```
 *
 * Given both outputs you can recover the inputs; given one you cannot. That is
 * the sense in which a butterfly rearranges information rather than destroying
 * it, and it is invisible when the same eight leaves are read one frame at a
 * time.
 *
 * **This diagram IS direction-aware, unlike the two ARX ones.** ChaCha20's and
 * Salsa20's encrypt and decrypt specs are structurally identical, so one drawing
 * serves both. The NTT's are not: the forward multiplies BEFORE combining and
 * the inverse AFTER, so the twiddle box moves to the other side of the crossing.
 * Twofish is the closer precedent — its two rotations swap by direction. The
 * side it moves to is derived from wiring (`shape.kind`), never from which spec
 * is loaded.
 *
 * **The header names the group.** Every one of a layer's groups runs identical
 * arithmetic; the only things that differ are the coefficients and this group's
 * ζ. So the header carries the pairing distance and which group this is — the
 * NTT's equivalent of the ARX diagrams' state-word indices. The group COUNT is
 * counted within this layer's own iterate scope, because the NTT has seven
 * sibling iterates running 1, 2, 4 … 64 groups and a trace-wide maximum would
 * label layer 1's only group "1 of 64".
 *
 * Interaction mirrors the other three diagrams: the element containing the
 * active leaf is accented ("you are here"), and clicking an element scrubs to
 * its frame. Every element here is a single leaf, so every box scrubs exactly.
 */

import {
  type NttButterflyDiagramModel,
  findActiveNttButterfly,
  nttButterflyDiagramModel,
} from "@/core/ntt-diagram";
import { canonicalStepId, iterateScopeKey } from "@/core/step-id";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";

type Props = {
  frame: TraceFrame;
};

const EMPTY_INDEX_MAP: ReadonlyMap<string, number> = new Map();

export const NttButterflyDiagram = (props: Props) => {
  const spec = useSpec();
  const version = useTraceVersion();

  const model = createMemo<NttButterflyDiagramModel | null>(() => {
    void version();
    const active = findActiveNttButterfly(props.frame, spec());
    if (!active) return null;

    // Groups run by THIS layer, not by the trace. The NTT is the spec that
    // broke every trace-wide `blockIndex` reading — see `iterateScopeKey`.
    const scope = iterateScopeKey(props.frame.path);
    let groupCount: number | null = null;
    const t = getTrace();
    if (t) {
      let max = -1;
      for (const f of t.frames) {
        if (f.blockIndex === undefined) continue;
        if (iterateScopeKey(f.path) !== scope) continue;
        if (f.blockIndex > max) max = f.blockIndex;
      }
      if (max >= 0) groupCount = max + 1;
    }

    return nttButterflyDiagramModel(
      active.layer,
      active.shape,
      props.frame.blockIndex ?? null,
      groupCount,
    );
  });

  /**
   * Frame index per drawn leaf in the ACTIVE group — drives click-to-scrub.
   * Matching on `blockIndex` keeps the scrub inside the group the user is
   * looking at, exactly as the Feistel, Twofish and ARX diagrams do.
   */
  const frameIndexByLeafId = createMemo<ReadonlyMap<string, number>>(() => {
    void version();
    const m = model();
    if (!m) return EMPTY_INDEX_MAP;
    const t = getTrace();
    if (!t) return EMPTY_INDEX_MAP;
    const blockIdx = props.frame.blockIndex;
    const scope = iterateScopeKey(props.frame.path);
    const wanted = new Set(m.drawnIds);
    const map = new Map<string, number>();
    for (let i = 0; i < t.frames.length; i++) {
      const f = t.frames[i];
      if (!f) continue;
      const id = canonicalStepId(f.stepId);
      if (!wanted.has(id) || map.has(id)) continue;
      // Scope AND block: two sibling layers can hold leaves of the same name.
      if (iterateScopeKey(f.path) !== scope) continue;
      if (blockIdx === undefined ? f.blockIndex !== undefined : f.blockIndex !== blockIdx) continue;
      map.set(id, i);
    }
    return map;
  });

  return (
    <Show when={model()}>
      {(getModel) => (
        <section class="ntt-butterfly-diagram" aria-label="ntt butterfly diagram">
          <div class="ntt-butterfly-diagram-header">
            <span class="ntt-butterfly-diagram-title">{getModel().butterflyName} butterfly</span>
            <code class="ntt-butterfly-diagram-kind">
              {`pairs j with j + ${getModel().pairingDistance}`}
              <Show when={getModel().groupIndex !== null}>
                {` · group ${(getModel().groupIndex ?? 0) + 1}`}
                <Show when={getModel().groupCount !== null}>{` of ${getModel().groupCount}`}</Show>
              </Show>
            </code>
          </div>
          <DiagramSvg
            model={getModel()}
            activeLeafId={canonicalStepId(props.frame.stepId)}
            frameIndexByLeafId={frameIndexByLeafId()}
          />
          <p class="ntt-butterfly-diagram-note muted small">
            Two coefficients in, two out, and <strong>each output depends on both inputs</strong> —
            so given the pair you can recover the originals, and given one of them you cannot. That
            is what makes the transform invertible rather than merely a mixing function.{" "}
            <Show
              when={getModel().kind === "cooley-tukey"}
              fallback={
                <>
                  The inverse combines <em>first</em> and twists <em>afterwards</em>; the forward
                  does it the other way round. They are different shapes, not the same shape with a
                  sign flipped.
                </>
              }
            >
              <>
                The twiddle multiply happens <em>before</em> the sum and difference are formed; the
                inverse butterfly does it <em>afterwards</em>. They are different shapes, not the
                same shape with a sign flipped.
              </>
            </Show>{" "}
            <span class="ntt-butterfly-diagram-ref">{getModel().reference}</span>
          </p>
        </section>
      )}
    </Show>
  );
};

// ─── SVG geometry ─────────────────────────────────────────────────────────
//
// Two horizontal rails (lo above, hi below), a split endpoint at the left and a
// recombine endpoint at the right, and one or two columns of boxes between
// them. The CROSSING column is the picture's whole point, so it is drawn as two
// diagonal connectors that genuinely cross.
//
// Routing rule, the one the Twofish diagram learned by looking: a wire may
// cross another wire, but must never pass through a labelled box. Satisfied by
// construction here — each column owns its own x, the diagonals live strictly
// between two columns' x-ranges, and nothing is drawn in that gap.

const RAIL_Y = { lo: 42, hi: 104 } as const;
const RAIL_LABEL_X = 10;

const ENDPOINT_W = 54;
const ENDPOINT_H = 22;
const SPLIT_X = 44;

const COL_X0 = 148;
const COL_PITCH = 108;

const BOX_W = 52;
const BOX_H = 22;

const OUT_LABEL_GAP = 16;

/** Where the rails begin, after the split's fan-out, and where they end. */
const RAIL_START_X = SPLIT_X + ENDPOINT_W / 2 + 18;
const FAN_IN_GAP = 18;

const railY = (rail: "lo" | "hi"): number => RAIL_Y[rail];
const colX = (i: number): number => COL_X0 + i * COL_PITCH;

/**
 * The x-span of the crossing's diagonals: from the right edge of whatever
 * precedes the crossing column to the left edge of its boxes.
 *
 * Computed rather than hardcoded because the crossing is the FIRST column in a
 * Gentleman–Sande butterfly (where the split precedes it) and the SECOND in a
 * Cooley–Tukey one (where the twiddle multiply does). Getting this wrong is not
 * subtle but it is silent: the first version collapsed both diagonals onto one
 * x, so the X rendered as a single vertical line between the rails.
 */
const crossSpan = (columnIndex: number): { readonly x1: number; readonly x2: number } => ({
  x1: Math.max(RAIL_START_X, colX(columnIndex) - COL_PITCH + BOX_W / 2 + 6),
  x2: colX(columnIndex) - BOX_W / 2 - 3,
});

const DiagramSvg = (props: {
  model: NttButterflyDiagramModel;
  activeLeafId: string;
  frameIndexByLeafId: ReadonlyMap<string, number>;
}) => {
  const m = (): NttButterflyDiagramModel => props.model;
  const columns = () => m().columns;
  const lastColX = () => colX(columns().length - 1);
  const recombineX = () => lastColX() + COL_PITCH;
  // Tail room for the written output lines. The longest is the inverse's
  // `hi′ = ζ · (hi − lo)` at 19 monospace characters — measured, because at the
  // first-drafted 96 it was clipped by the viewBox and simply vanished.
  const svgWidth = () => recombineX() + ENDPOINT_W / 2 + OUT_LABEL_GAP + 150;
  const svgHeight = 152;

  const scrubTo = (nodeId: string): void => {
    const idx = props.frameIndexByLeafId.get(nodeId);
    if (idx !== undefined) setFrame(idx);
  };

  /**
   * Keyboard parity with the Twofish and ARX diagrams: an element reachable by
   * click must be reachable by Tab + Enter/Space too.
   */
  const onKey = (nodeId: string) => (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      scrubTo(nodeId);
    }
  };

  /** `tabindex` only where there is actually a frame to scrub to. */
  const tab = (nodeId: string): number | undefined =>
    props.frameIndexByLeafId.has(nodeId) ? 0 : undefined;

  /** Class list for a clickable element, with the "you are here" accent. */
  const cls = (nodeId: string, base: string): string => {
    const active = nodeId === props.activeLeafId ? ` ${base}-active` : "";
    const clickable = props.frameIndexByLeafId.has(nodeId)
      ? " ntt-butterfly-diagram-clickable"
      : "";
    return `${base}${active}${clickable}`;
  };

  return (
    <svg
      class="ntt-butterfly-diagram-svg"
      width={svgWidth()}
      height={svgHeight}
      viewBox={`0 0 ${svgWidth()} ${svgHeight}`}
      role="img"
      aria-label={`${m().butterflyName} butterfly: a low and a high coefficient half crossing through a twiddle multiply`}
    >
      {/* ─── The two rails ─── */}
      <For each={["lo", "hi"] as const}>
        {(rail) => (
          <>
            <line
              x1={RAIL_START_X}
              y1={railY(rail)}
              x2={recombineX() - ENDPOINT_W / 2 - FAN_IN_GAP}
              y2={railY(rail)}
              class="ntt-butterfly-diagram-rail"
            />
            <text x={RAIL_LABEL_X} y={railY(rail) + 4} class="ntt-butterfly-diagram-rail-label">
              {rail}
            </text>
          </>
        )}
      </For>

      {/* ─── The crossing: two diagonals in the gap BEFORE the crossing column.
             Each output reads the other rail, which is the whole picture. ─── */}
      <For each={columns()}>
        {(column, i) => (
          <Show when={column.crossing}>
            <>
              <line
                x1={crossSpan(i()).x1}
                y1={railY("lo")}
                x2={crossSpan(i()).x2}
                y2={railY("hi")}
                class="ntt-butterfly-diagram-cross"
              />
              <line
                x1={crossSpan(i()).x1}
                y1={railY("hi")}
                x2={crossSpan(i()).x2}
                y2={railY("lo")}
                class="ntt-butterfly-diagram-cross"
              />
            </>
          </Show>
        )}
      </For>

      {/* ─── The ζ feed into the twiddle multiply, dropped from below so it
             crosses nothing. ─── */}
      <For each={columns()}>
        {(column, i) => (
          <For each={column.boxes.filter((b) => b.glyph.startsWith("×"))}>
            {(b) => (
              <>
                <line
                  x1={colX(i())}
                  y1={railY(b.rail) + BOX_H / 2 + 20}
                  x2={colX(i())}
                  y2={railY(b.rail) + BOX_H / 2}
                  class="ntt-butterfly-diagram-zeta-feed"
                />
                <text
                  x={colX(i())}
                  y={railY(b.rail) + BOX_H / 2 + 32}
                  class="ntt-butterfly-diagram-zeta-label"
                >
                  ζ
                </text>
              </>
            )}
          </For>
        )}
      </For>

      {/* ─── The split, feeding both rails ─── */}
      <g
        class={cls(m().splitId, "ntt-butterfly-diagram-endpoint")}
        onClick={() => scrubTo(m().splitId)}
        onKeyDown={onKey(m().splitId)}
        tabindex={tab(m().splitId)}
      >
        <title>the group's coefficients, cut into a low and a high half</title>
        <rect
          x={SPLIT_X - ENDPOINT_W / 2}
          y={(railY("lo") + railY("hi")) / 2 - ENDPOINT_H / 2}
          width={ENDPOINT_W}
          height={ENDPOINT_H}
          rx={3}
          class="ntt-butterfly-diagram-box"
        />
        <text
          x={SPLIT_X}
          y={(railY("lo") + railY("hi")) / 2 + 4}
          class="ntt-butterfly-diagram-box-label"
        >
          split
        </text>
      </g>
      {/* Split → each rail. Drawn as two short diagonals into the rails' starts. */}
      <For each={["lo", "hi"] as const}>
        {(rail) => (
          <line
            x1={SPLIT_X + ENDPOINT_W / 2}
            y1={(railY("lo") + railY("hi")) / 2}
            x2={RAIL_START_X}
            y2={railY(rail)}
            class="ntt-butterfly-diagram-rail"
          />
        )}
      </For>

      {/* ─── The operation boxes ─── */}
      <For each={columns()}>
        {(column, i) => (
          <For each={column.boxes}>
            {(b) => (
              <g
                class={cls(b.nodeId, "ntt-butterfly-diagram-op")}
                onClick={() => scrubTo(b.nodeId)}
                onKeyDown={onKey(b.nodeId)}
                tabindex={tab(b.nodeId)}
              >
                <title>{b.line}</title>
                <rect
                  x={colX(i()) - BOX_W / 2}
                  y={railY(b.rail) - BOX_H / 2}
                  width={BOX_W}
                  height={BOX_H}
                  rx={3}
                  class="ntt-butterfly-diagram-box"
                />
                <text x={colX(i())} y={railY(b.rail) + 4} class="ntt-butterfly-diagram-box-label">
                  {b.glyph}
                </text>
              </g>
            )}
          </For>
        )}
      </For>

      {/* ─── The recombine, and the two output lines it names ─── */}
      <g
        class={cls(m().recombineId, "ntt-butterfly-diagram-endpoint")}
        onClick={() => scrubTo(m().recombineId)}
        onKeyDown={onKey(m().recombineId)}
        tabindex={tab(m().recombineId)}
      >
        <title>the two transformed halves, put back low then high</title>
        <rect
          x={recombineX() - ENDPOINT_W / 2}
          y={(railY("lo") + railY("hi")) / 2 - ENDPOINT_H / 2}
          width={ENDPOINT_W}
          height={ENDPOINT_H}
          rx={3}
          class="ntt-butterfly-diagram-box"
        />
        <text
          x={recombineX()}
          y={(railY("lo") + railY("hi")) / 2 + 4}
          class="ntt-butterfly-diagram-box-label"
        >
          rejoin
        </text>
      </g>
      <For each={["lo", "hi"] as const}>
        {(rail) => (
          <line
            x1={recombineX() - ENDPOINT_W / 2 - FAN_IN_GAP}
            y1={railY(rail)}
            x2={recombineX() - ENDPOINT_W / 2}
            y2={(railY("lo") + railY("hi")) / 2}
            class="ntt-butterfly-diagram-rail"
          />
        )}
      </For>

      {/* The written line each rail carries out, to the right of the rejoin. */}
      <For each={columns().flatMap((c) => c.boxes)}>
        {(b) => (
          <Show when={b.role === "lo" || b.role === "hi"}>
            <text
              x={recombineX() + ENDPOINT_W / 2 + OUT_LABEL_GAP}
              y={railY(b.rail) + 4}
              class="ntt-butterfly-diagram-out-label"
            >
              {b.line}
            </text>
          </Show>
        )}
      </For>
    </svg>
  );
};
