import { type ByteFormat, formatByte } from "@/core/format";
import type { MatrixState, State, TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { lookupProvenance } from "../provenance/registry";
import { useByteFormat } from "../stores/format";
import {
  clearProvenanceHover,
  setProvenanceHover,
  useProvenanceHover,
} from "../stores/provenance-hover";

type Props = {
  before: MatrixState;
  after: MatrixState;
  /**
   * Same-stepId after-state from the immediately prior run. The caller can
   * pass any State variant — if the prior run had a different shape at this
   * stepId (e.g. user changed padding scheme between runs and the stepId
   * now points to a BytesState), MatrixView quietly suppresses the overlay
   * rather than crashing on the matrix-shaped index reads. Only matrix-
   * shaped states render as the third grid.
   */
  previousAfter?: State | null;
  /**
   * The trace frame this view is rendering. Optional — when provided,
   * enables Phase-3 cell-level provenance hover: hovering an `after` cell
   * lights up its source cells in `before` (and in the RoundKeyPanel, via
   * the shared `useProvenanceHover` signal). Synthetic-MatrixState tests
   * (round-key panel's TinyMatrix wrapper, palette previews, anywhere
   * outside the linear-mode trace surface) omit the prop and get the
   * pre-Phase-3 behavior with hover inert. App.tsx always passes it.
   */
  frame?: TraceFrame;
};

/**
 * Side-by-side byte grids: before / after / (optional) previous-run after.
 * Bytes render in the currently-selected format (hex / decimal / ASCII)
 * from the format store. The "after" grid highlights cells that changed
 * vs the "before" of THIS step; the "previous run" grid (if present)
 * highlights cells whose value differs from the current run's after-state
 * — that's the run-to-run diff.
 */
export const MatrixView = (props: Props) => {
  const fmt = useByteFormat();
  // Belts-and-braces guard: callers should only pass a previousAfter whose
  // shape is `matrix4x4-bytes`. If a future code path slips a different
  // shape through (e.g. the user changed padding scheme between runs and
  // the same stepId now points to a BytesState), treat it as "no overlay"
  // rather than crashing on the index reads below.
  const safePreviousAfter = () => {
    if (!props.previousAfter) return null;
    if (props.previousAfter.shape !== "matrix4x4-bytes") return null;
    return props.previousAfter;
  };
  const cells = () => {
    const prev = safePreviousAfter();
    const out: {
      row: number;
      col: number;
      before: number;
      after: number;
      prev: number | null;
      changed: boolean;
      diffPrev: boolean;
    }[] = [];
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        const idx = r + 4 * c;
        const b = props.before.bytes[idx] ?? 0;
        const a = props.after.bytes[idx] ?? 0;
        const p = prev ? (prev.bytes[idx] ?? 0) : null;
        out.push({
          row: r,
          col: c,
          before: b,
          after: a,
          prev: p,
          changed: a !== b,
          diffPrev: p !== null && p !== a,
        });
      }
    }
    return out;
  };

  // ─── Phase-3 hover wiring ──────────────────────────────────────────
  // Subscribe to the shared hover signal so the `before` grid lights up
  // the provenance sources when the user hovers a cell in `after`. We
  // gate by stepId so a stale hover from a prior frame can't paint cells
  // here after the user scrubs to a different frame.
  const hover = useProvenanceHover();
  // Map of `before` cell linear index → optional coefficient label
  // ("× 0x02" for MixColumns, undefined when the provenance source carries
  // no annotation). `.has(i)` drives the outline class; `.get(i)` drives
  // the small overlay label. Empty when no hover, or when the hovered
  // frame doesn't match this view's frame, or when the step has no
  // registered provenance fn.
  const beforeHighlights = createMemo<ReadonlyMap<number, string | undefined>>(() => {
    const h = hover();
    if (!h) return EMPTY_INDEX_MAP;
    if (props.frame === undefined) return EMPTY_INDEX_MAP;
    if (h.stepId !== props.frame.stepId) return EMPTY_INDEX_MAP;
    const out = new Map<number, string | undefined>();
    for (const src of h.sources) {
      if (src.kind === "before-cell") out.set(src.index, src.label);
    }
    return out;
  });

  // Per-cell hover handlers attached to the `after` grid. Cheap by
  // construction — both `enter` and `leave` are stable references so
  // the per-cell delegate doesn't allocate per render.
  const handleAfterEnter = (afterCellIndex: number): void => {
    const f = props.frame;
    if (f === undefined) return;
    const fn = lookupProvenance(f.stepType);
    if (!fn) return;
    const sources = fn(f, afterCellIndex);
    if (sources.length === 0) return;
    setProvenanceHover({ stepId: f.stepId, afterCellIndex, sources });
  };
  const handleAfterLeave = (): void => clearProvenanceHover();

  return (
    <div class="matrix-view">
      <Grid
        title="before"
        cells={cells()}
        field="before"
        format={fmt()}
        provenanceSourceIndices={beforeHighlights()}
      />
      <Grid
        title="after"
        cells={cells()}
        field="after"
        highlightChanged
        format={fmt()}
        onCellMouseEnter={handleAfterEnter}
        onCellMouseLeave={handleAfterLeave}
      />
      <Show when={safePreviousAfter()}>
        <Grid title="previous run" cells={cells()} field="prev" highlightDiffPrev format={fmt()} />
      </Show>
    </div>
  );
};

/** Allocation-free empty map; shared sentinel so the memo's "no hover"
 *  branch never produces a new object. The map is mutated in the populated
 *  branch — `EMPTY_INDEX_MAP` itself is treated as immutable here. */
const EMPTY_INDEX_MAP: ReadonlyMap<number, string | undefined> = new Map();

const Grid = (props: {
  title: string;
  cells: {
    row: number;
    col: number;
    before: number;
    after: number;
    prev: number | null;
    changed: boolean;
    diffPrev: boolean;
  }[];
  field: "before" | "after" | "prev";
  highlightChanged?: boolean;
  highlightDiffPrev?: boolean;
  format: ByteFormat;
  /**
   * Linear cell index (row + 4*col) → optional coefficient label.
   * `.has(i)` drives the `.provenance-source` outline class — populated
   * only on the `before` grid when a sibling `after` cell is being hovered.
   * `.get(i)` returns the small annotation text (`× 0x02`, `× 0x0e`, …)
   * rendered in the cell's top-right corner; undefined when the
   * provenance source carries no label (SubBytes, ShiftRows, identity
   * MixColumns coefficient). Per the declared precedence: when
   * `.provenance-source` applies, it wins over `.changed` / `.diff-vs-prev`.
   */
  provenanceSourceIndices?: ReadonlyMap<number, string | undefined>;
  /** Hover handler attached to each cell in the `after` grid. Receives
   *  the linear cell index (row + 4*col). */
  onCellMouseEnter?: (afterCellIndex: number) => void;
  onCellMouseLeave?: () => void;
}) => (
  <div class="grid-block">
    <div class="grid-title">{props.title}</div>
    <div class="grid">
      <For each={props.cells}>
        {(cell) => {
          // `linearIndex` is stable per cell (the row/col never change
          // inside one render's lifecycle), so binding it as a local
          // const is safe. The PROVENANCE check, however, depends on
          // a reactive prop (`provenanceSourceIndices`) — that read
          // MUST stay inline in the classList so Solid re-evaluates it
          // when the prop changes. See CLAUDE.md gotcha: "For callbacks
          // aren't reactive scopes."
          const linearIndex = cell.row + 4 * cell.col;
          return (
            <div
              class="cell"
              classList={{
                // Precedence (per plan): provenance-source > diff-vs-prev > changed.
                // Each predicate reads props inline so the classList object
                // re-evaluates on hover / format / frame change.
                "provenance-source": !!props.provenanceSourceIndices?.has(linearIndex),
                changed:
                  !props.provenanceSourceIndices?.has(linearIndex) &&
                  !!props.highlightChanged &&
                  cell.changed,
                "diff-vs-prev":
                  !props.provenanceSourceIndices?.has(linearIndex) &&
                  !!props.highlightDiffPrev &&
                  cell.diffPrev,
              }}
              style={{ "grid-row": `${cell.row + 1}`, "grid-column": `${cell.col + 1}` }}
              onMouseEnter={() => props.onCellMouseEnter?.(linearIndex)}
              onMouseLeave={() => props.onCellMouseLeave?.()}
            >
              {/* Inline rather than via a const so `props.format` is read
                  inside JSX — that's what makes the cell text react to a
                  later setByteFormat() call. A captured const value isn't
                  reactive. The "prev" field can be null when overlay is on
                  but the prior trace lacked this stepId; render a blank
                  instead of a misleading "0". */}
              {props.field === "prev"
                ? cell.prev === null
                  ? ""
                  : formatByte(cell.prev, props.format)
                : formatByte(cell[props.field] as number, props.format)}
              {/* Provenance coefficient label (MixColumns × 0x02 / × 0x03 /
                  × 0x0e / etc.). Inline read so the label appears as soon
                  as the hover memo updates. `<Show>`'s callback form
                  passes a non-nullish accessor — empty string is falsy,
                  but our labels are always non-empty when present. */}
              <Show when={props.provenanceSourceIndices?.get(linearIndex)}>
                {(label) => <span class="provenance-label">{label()}</span>}
              </Show>
            </div>
          );
        }}
      </For>
    </div>
  </div>
);
