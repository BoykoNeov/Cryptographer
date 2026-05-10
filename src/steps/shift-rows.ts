import type { Json, MatrixState, StepExecutor } from "../core/types";
import { matAt, setMatAt } from "../core/state/matrix";

/**
 * Cyclically shift each row of the 4x4 state to the left by `shifts[r]` columns.
 * Standard AES uses [0, 1, 2, 3]; inverse uses [0, 3, 2, 1] (or equivalently
 * a right shift of [0, 1, 2, 3]).
 *
 * params: { shifts: [number, number, number, number] }
 */
export const shiftRows: StepExecutor = (state, params) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("shift-rows expects matrix4x4-bytes state");
  }
  const shifts = readShifts(params);
  const next = new Uint8Array(16);
  for (let r = 0; r < 4; r++) {
    const shift = shifts[r] ?? 0;
    for (let c = 0; c < 4; c++) {
      const srcCol = (c + shift) % 4;
      setMatAt(next, r, c, matAt(state, r, srcCol));
    }
  }
  const result: MatrixState = { shape: "matrix4x4-bytes", bytes: next };
  return { state: result };
};

const readShifts = (params: Json): readonly number[] => {
  if (
    typeof params !== "object" ||
    params === null ||
    Array.isArray(params) ||
    !("shifts" in params)
  ) {
    throw new Error("shift-rows requires params.shifts");
  }
  const shifts = (params as { shifts: unknown }).shifts;
  if (!Array.isArray(shifts) || shifts.length !== 4) {
    throw new Error("shifts must be an array of 4 numbers");
  }
  return shifts as readonly number[];
};
