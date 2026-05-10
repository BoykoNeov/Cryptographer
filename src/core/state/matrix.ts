import type { MatrixState } from "../types";

/**
 * AES state is a 4×4 byte matrix in column-major order: byte at row r, col c
 * lives at index r + 4*c. FIPS-197 §3.4.
 */

export const matrixFromBytes = (bytes: Uint8Array): MatrixState => {
  if (bytes.length !== 16) throw new Error("matrix4x4 needs 16 bytes");
  return { shape: "matrix4x4-bytes", bytes: new Uint8Array(bytes) };
};

export const cloneMatrix = (m: MatrixState): MatrixState => ({
  shape: "matrix4x4-bytes",
  bytes: new Uint8Array(m.bytes),
});

export const matAt = (m: MatrixState, row: number, col: number): number =>
  m.bytes[row + 4 * col] ?? 0;

export const setMatAt = (buf: Uint8Array, row: number, col: number, value: number): void => {
  buf[row + 4 * col] = value & 0xff;
};

// ─── GF(2^8) arithmetic over the AES polynomial x^8 + x^4 + x^3 + x + 1 ───

/** GF(2^8) multiply by 2 (xtime). FIPS-197 §4.2.1. */
export const xtime = (b: number): number => {
  const shifted = (b << 1) & 0xff;
  return (b & 0x80) !== 0 ? shifted ^ 0x1b : shifted;
};

/** GF(2^8) multiply, peasant's algorithm. */
export const gfMul = (a: number, b: number): number => {
  let result = 0;
  let x = a & 0xff;
  let y = b & 0xff;
  for (let i = 0; i < 8; i++) {
    if ((y & 1) !== 0) result ^= x;
    x = xtime(x);
    y >>>= 1;
  }
  return result & 0xff;
};
