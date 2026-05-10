import { gfMul, matAt, setMatAt } from "../core/state/matrix";
import type { Json, MatrixState, StepExecutor } from "../core/types";

/**
 * Multiply each column of the 4x4 state by a 4x4 GF(2^8) matrix.
 * AES forward: [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]].
 * Inverse: [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]].
 *
 * params: { matrix: number[4][4] }  // row-major coefficients
 */
export const mixColumns: StepExecutor = (state, params) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("mix-columns expects matrix4x4-bytes state");
  }
  const m = readMatrix(params);
  const next = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      let acc = 0;
      const row = m[r] as readonly number[];
      for (let k = 0; k < 4; k++) {
        acc ^= gfMul(row[k] ?? 0, matAt(state, k, c));
      }
      setMatAt(next, r, c, acc);
    }
  }
  const result: MatrixState = { shape: "matrix4x4-bytes", bytes: next };
  return { state: result };
};

const readMatrix = (params: Json): readonly (readonly number[])[] => {
  if (
    typeof params !== "object" ||
    params === null ||
    Array.isArray(params) ||
    !("matrix" in params)
  ) {
    throw new Error("mix-columns requires params.matrix");
  }
  const matrix = (params as { matrix: unknown }).matrix;
  if (!Array.isArray(matrix) || matrix.length !== 4) {
    throw new Error("matrix must be a 4x4 array");
  }
  for (const row of matrix) {
    if (!Array.isArray(row) || row.length !== 4) {
      throw new Error("matrix must be a 4x4 array");
    }
  }
  return matrix as readonly (readonly number[])[];
};
