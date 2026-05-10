/**
 * 4x4 hex byte editor for the MixColumns matrix. Coefficients are GF(2^8)
 * field elements (0..255) — each column of the cipher's state matrix is
 * multiplied by this matrix in the GF(2^8) field defined by the AES
 * polynomial.
 *
 * Forward AES matrix is mostly small constants {1, 2, 3}; inverse matrix
 * is {9, 11, 13, 14}. Letting users edit these is a quick way to break the
 * cipher in interesting ways — try replacing the matrix with the identity
 * to see SubBytes + ShiftRows on their own.
 */

import { For } from "solid-js";
import { HexCellInput } from "./HexCellInput";

type Props = {
  matrix: readonly (readonly number[])[];
  onChange: (next: number[][]) => void;
};

export const MatrixEditor = (props: Props) => {
  const rows = [0, 1, 2, 3];
  const cols = [0, 1, 2, 3];

  return (
    <div class="matrix-editor">
      <For each={rows}>
        {(r) => (
          <div class="matrix-row">
            <For each={cols}>
              {(c) => (
                <HexCellInput
                  value={props.matrix[r]?.[c] ?? 0}
                  onCommit={(next) => {
                    // Deep clone — if we returned a partially-shared array,
                    // updateAllStepsByType's reference-equality short-circuit
                    // could make a real edit look like a no-op.
                    const out = props.matrix.map((row) => [...row]);
                    if (out[r]) out[r][c] = next;
                    props.onChange(out);
                  }}
                />
              )}
            </For>
          </div>
        )}
      </For>
    </div>
  );
};
