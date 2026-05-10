/**
 * Compact 4×4 byte grid for thumbnails in the neighborhood strip.
 * Renders the bytes of a MatrixState as a small 4×4 of hex pairs — no
 * editing, no diff highlighting, just a glance-able snapshot.
 */

import type { MatrixState } from "@/core/types";
import { For } from "solid-js";

type Props = {
  state: MatrixState;
};

export const TinyMatrix = (props: Props) => {
  // Iterate column-then-row to walk the column-major byte storage in
  // the same visual order the rendering expects (row r, col c → r + 4*c).
  const cells = (): { row: number; col: number; byte: number }[] => {
    const out: { row: number; col: number; byte: number }[] = [];
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        out.push({ row: r, col: c, byte: props.state.bytes[r + 4 * c] ?? 0 });
      }
    }
    return out;
  };

  return (
    <div class="tiny-matrix">
      <For each={cells()}>
        {(cell) => (
          <div
            class="tiny-cell"
            style={{ "grid-row": `${cell.row + 1}`, "grid-column": `${cell.col + 1}` }}
          >
            {cell.byte.toString(16).padStart(2, "0")}
          </div>
        )}
      </For>
    </div>
  );
};
