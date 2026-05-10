import type { Json, MatrixState, StepExecutor } from "../core/types";

/**
 * XOR a 16-byte round key (read from aux) into the state matrix, byte-wise.
 *
 * params: { auxName: string }
 *   The named aux entry must be a Uint8Array of length 16.
 */
export const addRoundKey: StepExecutor = (state, params, ctx) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("add-round-key expects matrix4x4-bytes state");
  }
  const auxName = readAuxName(params);
  const rk = ctx.aux.get(auxName);
  if (!(rk instanceof Uint8Array) || rk.length !== 16) {
    throw new Error(`aux '${auxName}' must be a 16-byte Uint8Array`);
  }
  const next = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    next[i] = (state.bytes[i] ?? 0) ^ (rk[i] ?? 0);
  }
  const result: MatrixState = { shape: "matrix4x4-bytes", bytes: next };
  return { state: result, auxReads: [auxName] };
};

const readAuxName = (params: Json): string => {
  if (
    typeof params !== "object" ||
    params === null ||
    Array.isArray(params) ||
    !("auxName" in params)
  ) {
    throw new Error("add-round-key requires params.auxName");
  }
  const auxName = (params as { auxName: unknown }).auxName;
  if (typeof auxName !== "string") {
    throw new Error("auxName must be a string");
  }
  return auxName;
};
