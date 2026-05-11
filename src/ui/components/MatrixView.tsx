import { type ByteFormat, formatByte } from "@/core/format";
import type { MatrixState, State } from "@/core/types";
import { For, Show } from "solid-js";
import { useByteFormat } from "../stores/format";

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

  return (
    <div class="matrix-view">
      <Grid title="before" cells={cells()} field="before" format={fmt()} />
      <Grid title="after" cells={cells()} field="after" highlightChanged format={fmt()} />
      <Show when={safePreviousAfter()}>
        <Grid title="previous run" cells={cells()} field="prev" highlightDiffPrev format={fmt()} />
      </Show>
    </div>
  );
};

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
}) => (
  <div class="grid-block">
    <div class="grid-title">{props.title}</div>
    <div class="grid">
      <For each={props.cells}>
        {(cell) => (
          <div
            class="cell"
            classList={{
              changed: !!props.highlightChanged && cell.changed,
              "diff-vs-prev": !!props.highlightDiffPrev && cell.diffPrev,
            }}
            style={{ "grid-row": `${cell.row + 1}`, "grid-column": `${cell.col + 1}` }}
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
          </div>
        )}
      </For>
    </div>
  </div>
);
