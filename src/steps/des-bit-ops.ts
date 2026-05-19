/**
 * Bit-level helpers shared by the DES step executors. Mirrors the helpers
 * in `scripts/verify-des.mjs` (the Phase-1 verification oracle) so the
 * runtime steps and the oracle agree byte-for-byte on intermediate values.
 *
 * **Bit numbering: FIPS 46-3 convention.** Bits are 1-indexed and MSB-first
 * within each byte. For an N-byte buffer `buf` and FIPS bit index `i` (1..8N):
 *
 *     bit_i = (buf[(i-1) >> 3] >> (7 - ((i-1) & 7))) & 1
 *
 * That is, bit 1 = the MSB of byte 0; bit 8 = the LSB of byte 0; bit 9 = MSB
 * of byte 1; bit 64 = the LSB of byte 7.
 *
 * **Why a DES-specific helpers file, not extending `serpent-bit-ops.ts`.**
 * Serpent's `applyBitPermutation` is hardcoded to 16-byte input and uses
 * LSB-first numbering (state bit 0 = LSB of byte 0). DES uses MSB-first AND
 * varies its buffer length across 4-byte (32-bit state) / 6-byte (48-bit
 * S-box input) / 8-byte (64-bit IP/FP). Generalizing Serpent's helper to
 * take a bit-convention flag + variable length would touch Serpent's hot
 * path; mirroring the oracle's helpers in a separate file is the lower-
 * blast-radius option and keeps the bit-numbering convention literal in
 * the helper's name.
 *
 * All exported helpers are pure; they never mutate their input arrays.
 */

/**
 * Read FIPS bit `i` (1-indexed, MSB-first) from `buf`. Returns 0 or 1.
 * Out-of-range indices return 0 (matches the oracle's tolerance — but the
 * permutation tables in `des-constants.ts` only reference valid indices).
 */
export const readFipsBit = (buf: Uint8Array, i: number): number => {
  const byteIdx = (i - 1) >> 3;
  const bitIdx = 7 - ((i - 1) & 7);
  return ((buf[byteIdx] ?? 0) >> bitIdx) & 1;
};

/**
 * Pack a bit array (each element 0 or 1) into a byte buffer using FIPS
 * MSB-first numbering. Output length is `ceil(bits.length / 8)`; trailing
 * bits in the last byte are zero. Allocates fresh.
 *
 * Example: `bitsToFipsBytes([1,0,1,0,1,0,1,0])` returns `Uint8Array([0xaa])`.
 */
export const bitsToFipsBytes = (bits: readonly number[]): Uint8Array => {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) {
      const idx = i >> 3;
      out[idx] = (out[idx] ?? 0) | (1 << (7 - (i & 7)));
    }
  }
  return out;
};

/**
 * Unpack the first `nBits` of `buf` into a bit array of length `nBits`,
 * FIPS MSB-first. Inverse of `bitsToFipsBytes` (up to trailing zeros).
 */
export const fipsBytesToBits = (buf: Uint8Array, nBits: number): number[] => {
  const bits = new Array<number>(nBits);
  for (let i = 0; i < nBits; i++) bits[i] = readFipsBit(buf, i + 1);
  return bits;
};

/**
 * Apply a permutation table (FIPS 1-indexed, MSB-first) to `input`. The
 * output has `outLen` bits, packed into a `ceil(outLen / 8)`-byte buffer.
 *
 *   output_bit_(i+1) = input_bit_(table[i])     for i in 0..outLen-1
 *
 * Used directly by IP, FP, E, P, PC-1, PC-2 — only the table and lengths
 * differ. Allocates fresh; never mutates `input`.
 *
 * Throws when `table.length !== outLen` (programming error — the table is
 * what defines the output length).
 */
export const fipsPermute = (
  input: Uint8Array,
  table: readonly number[],
  outLen: number,
): Uint8Array => {
  if (table.length !== outLen) {
    throw new Error(`fipsPermute: table.length (${table.length}) must equal outLen (${outLen})`);
  }
  const bits = new Array<number>(outLen);
  for (let i = 0; i < outLen; i++) {
    bits[i] = readFipsBit(input, table[i] ?? 0);
  }
  return bitsToFipsBytes(bits);
};

/**
 * Left-rotate the first `nBits` of `bits` by `n` positions (cyclic). The
 * array is treated as a length-`nBits` bit sequence; trailing array entries
 * are ignored. Returns a fresh array of length `nBits`.
 *
 * Used by the DES key schedule's per-round shifts on the 28-bit C/D halves.
 */
export const rotateBitsLeft = (bits: readonly number[], n: number, nBits: number): number[] => {
  const out = new Array<number>(nBits);
  const shift = ((n % nBits) + nBits) % nBits;
  for (let i = 0; i < nBits; i++) out[i] = bits[(i + shift) % nBits] ?? 0;
  return out;
};
