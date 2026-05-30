// GF(2^8) arithmetic over the AES polynomial x^8 + x^4 + x^3 + x + 1.
//
// Phase 5 Slice 5.1 (2026-05-30) retired the `MatrixState`-typed helpers
// (`matrixFromBytes` / `cloneMatrix` / `matAt` / `setMatAt`) along with the
// `matrix4x4-bytes` State shape and the test-only matrix AES round
// primitives. The GF field math below is shape-agnostic and still used by
// the shipped port-native `gf-matrix-multiply@1` MixColumns primitive, so it
// stays. (FIPS-197 §3.4's column-major byte layout — `state[r + 4*c]` — now
// lives only as the advisory `PortLayout "matrix-cm-4x4"` rendering tag.)

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
