/**
 * Compact 4×4 byte grid for thumbnails in the neighborhood strip.
 * Renders the bytes of a MatrixState in the global byte format — no
 * editing. Optionally compares each cell against an equivalent "previous
 * run" state and outlines cells whose value differs (the Phase 2b
 * run-to-run diff overlay, in miniature).
 */

import { formatByte } from "@/core/format";
import type { MatrixState } from "@/core/types";
import { For } from "solid-js";
import { useByteFormat } from "../stores/format";

type Props = {
  state: MatrixState;
  /**
   * Same-stepId after-state from the prior run, when overlay mode is on.
   * Cells where this differs from `state` get a ring. Pass null/undefined
   * to disable the overlay for this thumbnail.
   */
  previousState?: MatrixState | null;
  /**
   * Linear cell indices (r + 4*c) to outline with the `.provenance-source`
   * class — populated by the RoundKeyPanel when an active hover's
   * `aux-cell` source points into this K_i. Per the declared precedence
   * (Phase 3 plan), `.provenance-source` wins over `.diff-vs-prev`, so
   * a hovered cell that ALSO differs from the previous run only shows
   * the provenance outline while the hover is active. Pass `undefined`
   * (or omit by union default) for the "no hover" case.
   */
  provenanceHighlights?: ReadonlySet<number> | undefined;
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
        const v = props.state.bytes[idx] ?? 0;
        const p = props.previousState ? (props.previousState.bytes[idx] ?? 0) : null;
        out.push({ row: r, col: c, byte: v, diffPrev: p !== null && p !== v });
      }
    }
    return out;
  };

  return (
    <div class="tiny-matrix">
      <For each={cells()}>
        {(cell) => {
          // `linearIndex` is stable per cell — safe as a local const.
          // The provenance check, however, reads a reactive prop and
          // MUST stay inline in the classList. See CLAUDE.md gotcha:
          // "For callbacks aren't reactive scopes."
          const linearIndex = cell.row + 4 * cell.col;
          return (
            <div
              class="tiny-cell"
              classList={{
                // Same precedence as MatrixView: provenance-source wins
                // over diff-vs-prev when both would apply on the same cell.
                "provenance-source": !!props.provenanceHighlights?.has(linearIndex),
                "diff-vs-prev": !props.provenanceHighlights?.has(linearIndex) && cell.diffPrev,
              }}
              style={{ "grid-row": `${cell.row + 1}`, "grid-column": `${cell.col + 1}` }}
            >
              {formatByte(cell.byte, fmt())}
            </div>
          );
        }}
      </For>
    </div>
  );
};
