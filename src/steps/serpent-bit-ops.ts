/**
 * Bit-level helpers shared by the Serpent step executors.
 *
 * Serpent does most of its work in two views of the 128-bit state:
 *
 *   (a) as 16 individual bytes (for byte-wise XOR with round keys, and for
 *       moving bits around via the IP/FP permutation tables);
 *   (b) as four 32-bit little-endian words (for the Linear Transform's
 *       rotations and shifts, and for the bitsliced S-box application
 *       across the 32 columns of the four-word view).
 *
 * The conversions are trivial but error-prone (endianness, signed-int
 * shenanigans on rotation), so they live here in one place and are pinned
 * indirectly by the cipher KAT.
 *
 * Bit-numbering: state bit `b` is bit `b % 8` of byte `b >> 3`, LSB-first
 * within each byte. State bit 0 = LSB of byte 0; state bit 7 = MSB of byte 0;
 * state bit 8 = LSB of byte 1; state bit 127 = MSB of byte 15.
 */

/** Read a 32-bit little-endian word from `bytes` at `offset`. Returns an
 *  unsigned 32-bit integer (in the JS safe-integer range). */
export const readWordLE32 = (bytes: Uint8Array, offset: number): number => {
  return (
    ((bytes[offset] ?? 0) |
      ((bytes[offset + 1] ?? 0) << 8) |
      ((bytes[offset + 2] ?? 0) << 16) |
      ((bytes[offset + 3] ?? 0) << 24)) >>>
    0
  );
};

/** Write an unsigned 32-bit `word` as 4 little-endian bytes into `bytes` at
 *  `offset`. */
export const writeWordLE32 = (bytes: Uint8Array, offset: number, word: number): void => {
  bytes[offset] = word & 0xff;
  bytes[offset + 1] = (word >>> 8) & 0xff;
  bytes[offset + 2] = (word >>> 16) & 0xff;
  bytes[offset + 3] = (word >>> 24) & 0xff;
};

/** Decode a 16-byte buffer into four little-endian 32-bit words. */
export const bytesToWords4 = (bytes: Uint8Array): [number, number, number, number] => [
  readWordLE32(bytes, 0),
  readWordLE32(bytes, 4),
  readWordLE32(bytes, 8),
  readWordLE32(bytes, 12),
];

/** Encode four 32-bit words back to a 16-byte buffer. Allocates fresh. */
export const wordsToBytes4 = (w0: number, w1: number, w2: number, w3: number): Uint8Array => {
  const out = new Uint8Array(16);
  writeWordLE32(out, 0, w0);
  writeWordLE32(out, 4, w1);
  writeWordLE32(out, 8, w2);
  writeWordLE32(out, 12, w3);
  return out;
};

/** Left-rotate a 32-bit value by `n` bits. `n` must be in 0..31. Used by the
 *  key-expansion prekey recurrence (rotate by 11). */
export const rotl32 = (x: number, n: number): number =>
  (((x << n) | (x >>> (32 - n))) >>> 0) & 0xffffffff;

/** Read bit `b` (0..127) from a 16-byte state. Returns 0 or 1. */
export const readBit = (bytes: Uint8Array, b: number): number =>
  ((bytes[b >> 3] ?? 0) >> (b & 7)) & 1;

/** Set bit `b` (0..127) of a 16-byte state to `value` (0 or 1). Mutates `bytes`. */
export const writeBit = (bytes: Uint8Array, b: number, value: number): void => {
  const i = b >> 3;
  const mask = 1 << (b & 7);
  const current = bytes[i] ?? 0;
  bytes[i] = (current & ~mask) | (value & 1 ? mask : 0);
};

/**
 * Apply a 128-entry bit permutation. `output_bit[i] = input_bit[table[i]]`.
 *
 * Allocates fresh; never mutates `input`. The Serpent IP and FP both use
 * this exact form — only the table differs.
 */
export const applyBitPermutation = (input: Uint8Array, table: readonly number[]): Uint8Array => {
  if (input.length !== 16) {
    throw new Error(`bit permutation expects 16-byte input; got ${input.length}`);
  }
  if (table.length !== 128) {
    throw new Error(`bit permutation table must have 128 entries; got ${table.length}`);
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 128; i++) {
    const src = table[i] ?? 0;
    writeBit(out, i, readBit(input, src));
  }
  return out;
};

/**
 * Apply a 4-bit S-box bitsliced across four 32-bit words.
 *
 * For each bit position `j` in 0..31, the 4 bits at column `j` (one from each
 * of w0..w3) are assembled into a 4-bit value `in`, looked up in the S-box,
 * and written back to the same column of the output words.
 *
 * This is the "bitslice form" S-box, paired with the bitslice form of LT and
 * NO IP/FP. Our cipher uses the equivalent "standard form" (consecutive-
 * nibble S-box paired with IP/FP and the table form of LT), so this helper
 * is also used by the key schedule alone (where the bitslice form is what
 * produces the raw round-key words before IP is applied to them).
 */
export const sboxBitslice4 = (
  w0: number,
  w1: number,
  w2: number,
  w3: number,
  sbox: readonly number[],
): [number, number, number, number] => {
  if (sbox.length !== 16) {
    throw new Error(`bitsliced S-box expects 16 entries; got ${sbox.length}`);
  }
  let r0 = 0;
  let r1 = 0;
  let r2 = 0;
  let r3 = 0;
  for (let j = 0; j < 32; j++) {
    const inBits =
      ((w0 >>> j) & 1) |
      (((w1 >>> j) & 1) << 1) |
      (((w2 >>> j) & 1) << 2) |
      (((w3 >>> j) & 1) << 3);
    const out = sbox[inBits] ?? 0;
    r0 |= (out & 1) << j;
    r1 |= ((out >> 1) & 1) << j;
    r2 |= ((out >> 2) & 1) << j;
    r3 |= ((out >> 3) & 1) << j;
  }
  return [r0 >>> 0, r1 >>> 0, r2 >>> 0, r3 >>> 0];
};
