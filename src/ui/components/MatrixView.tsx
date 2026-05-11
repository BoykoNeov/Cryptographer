import { type ByteFormat, formatByte } from "@/core/format";
import type { MatrixState } from "@/core/types";
import { For } from "solid-js";
import { useByteFormat } from "../stores/format";

type Props = {
  before: MatrixState;
  after: MatrixState;
};

/**
 * Side-by-side 4×4 byte grids. Cells where the byte changed between
 * `before` and `after` are highlighted on the right. Bytes render in the
 * currently-selected format (hex / decimal / ASCII) from the format store.
 */
export const MatrixView = (props: Props) => {
  const fmt = useByteFormat();
  const cells = () => {
    const out: { row: number; col: number; before: number; after: number; changed: boolean }[] = [];
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        const idx = r + 4 * c;
        const b = props.before.bytes[idx] ?? 0;
        const a = props.after.bytes[idx] ?? 0;
        out.push({ row: r, col: c, before: b, after: a, changed: a !== b });
      }
    }
    return out;
  };

  return (
    <div class="matrix-view">
      <Grid title="before" cells={cells()} field="before" format={fmt()} />
      <Grid title="after" cells={cells()} field="after" highlightChanged format={fmt()} />
    </div>
  );
};

const Grid = (props: {
  title: string;
  cells: { row: number; col: number; before: number; after: number; changed: boolean }[];
  field: "before" | "after";
  highlightChanged?: boolean;
  format: ByteFormat;
}) => (
  <div class="grid-block">
    <div class="grid-title">{props.title}</div>
    <div class="grid">
      <For each={props.cells}>
        {(cell) => (
          <div
            class="cell"
            classList={{ changed: !!props.highlightChanged && cell.changed }}
            style={{ "grid-row": `${cell.row + 1}`, "grid-column": `${cell.col + 1}` }}
          >
            {formatByte(cell[props.field] as number, props.format)}
          </div>
        )}
      </For>
    </div>
  </div>
);
