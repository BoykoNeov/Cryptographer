import type { Json, MatrixState, StepExecutor } from "../core/types";

/**
 * Generic byte substitution: replace every byte b with sbox[b].
 * AES uses this for both SubBytes (forward) and InvSubBytes (with the inverse table).
 *
 * params: { sbox: number[] } — length 256, values 0..255.
 */
export const byteSubstitution: StepExecutor = (state, params) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("byte-substitution expects matrix4x4-bytes state");
  }
  const sbox = readSbox(params);
  const next = new Uint8Array(state.bytes);
  for (let i = 0; i < next.length; i++) {
    const b = next[i] ?? 0;
    next[i] = sbox[b] ?? 0;
  }
  const result: MatrixState = { shape: "matrix4x4-bytes", bytes: next };
  return { state: result };
};

const readSbox = (params: Json): readonly number[] => {
  if (
    typeof params !== "object" ||
    params === null ||
    Array.isArray(params) ||
    !("sbox" in params)
  ) {
    throw new Error("byte-substitution requires params.sbox");
  }
  const sbox = (params as { sbox: unknown }).sbox;
  if (!Array.isArray(sbox) || sbox.length !== 256) {
    throw new Error("sbox must be an array of 256 numbers");
  }
  return sbox as readonly number[];
};
