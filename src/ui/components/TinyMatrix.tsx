/**
 * Compact 4×4 byte grid for thumbnails — renders 16 bytes in the global
 * byte format, column-major (FIPS-197 §3.4: cell (r,c) at index `r + 4*c`),
 * no editing. Optionally compares each cell against an equivalent "previous
 * run" byte sequence and outlines cells whose value differs (the Phase 2b
 * run-to-run diff overlay, in miniature).
 *
 * Phase 5 Slice 5.1 (2026-05-30): the props were narrowed from `MatrixState`
 * to raw `Uint8Array` when the `matrix4x4-bytes` State shape was retired.
 * The "this 16-byte sequence reads as a 4×4 matrix" judgment is now the
 * caller's (the surviving live consumer is `RoundKeyPanel`, rendering
 * round keys) — exactly the advisory layout-tag posture the plan called for.
 */

import { formatByte } from "@/core/format";
import { For } from "solid-js";
import { useByteFormat } from "../stores/format";

type Props = {
  /** 16 bytes, column-major (AES State convention). */
  bytes: Uint8Array;
  /**
   * Same-stepId after-bytes from the prior run, when overlay mode is on.
   * Cells where this differs from `bytes` get a ring. Pass null/undefined
   * to disable the overlay for this thumbnail.
   */
  previousBytes?: Uint8Array | null;
};

export const TinyMatrix = (props: Props) => {
  const fmt = useByteFormat();
  // Iterate column-then-row to walk the column-major byte storage in
  // the same visual order the rendering expects (row r, col c → r + 4*c).
  const cells = (): { row: number; col: number; byte: number; diffPrev: boolean }[] => {
    const out: { row: number; col: number; byte: number; diffPrev: boolean }[] = [];
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        const idx = r + 4 * c;
        const v = props.bytes[idx] ?? 0;
        const p = props.previousBytes ? (props.previousBytes[idx] ?? 0) : null;
        out.push({ row: r, col: c, byte: v, diffPrev: p !== null && p !== v });
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
            classList={{ "diff-vs-prev": cell.diffPrev }}
            style={{ "grid-row": `${cell.row + 1}`, "grid-column": `${cell.col + 1}` }}
          >
            {formatByte(cell.byte, fmt())}
          </div>
        )}
      </For>
    </div>
  );
};
