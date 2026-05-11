/**
 * Speck byte ↔ word codec. Speck operates on n-bit words (n=16 for
 * Speck32/64, n=24/32/48/64 for larger variants) but the user-facing state
 * is a flat byte sequence. The mapping is convention-dependent:
 *
 *   • **BE-paper** — big-endian within each word, words written in the
 *     order they appear in the Beaulieu et al. 2013 paper.
 *       key bytes  → (l_{m-2}, l_{m-3}, …, l_0, k_0)   BE each
 *       block bytes → (x, y)                            BE each
 *
 *   • **LE-NSA** — little-endian within each word, k_0-first key order;
 *     matches the NSA reference C and SUPERCOP implementations.
 *       key bytes  → (k_0, l_0, l_1, …, l_{m-2})        LE each
 *       block bytes → (y, x)                            LE each
 *
 * The two conventions compute the IDENTICAL word-level cipher; only the
 * byte serialization at the input and output boundaries differs. Pick the
 * convention via the `byteOrder` step param. Both Speck-32/64 cipher specs
 * (BE and LE) share the same step code through this codec.
 */

import type { Json } from "../core/types";

export type SpeckByteOrder = "be-paper" | "le-nsa";

/** Decode `wordBits/8` bytes from `bytes` at `byteOffset` as one word. */
export const decodeWord = (
  bytes: Uint8Array,
  byteOffset: number,
  wordBits: number,
  order: SpeckByteOrder,
): number => {
  const wb = wordBits / 8;
  let w = 0;
  if (order === "be-paper") {
    // Big-endian: high byte first.
    for (let i = 0; i < wb; i++) {
      w = (w << 8) | (bytes[byteOffset + i] ?? 0);
    }
  } else {
    // Little-endian: low byte first.
    for (let i = wb - 1; i >= 0; i--) {
      w = (w << 8) | (bytes[byteOffset + i] ?? 0);
    }
  }
  // For wordBits ≤ 30, w fits in a JS number safely. Speck32/64 uses 16-bit
  // words; the larger Speck variants (with 32/48/64-bit words) would need
  // BigInt math here — out of scope for this commit.
  return w >>> 0;
};

/** Encode one word into `wordBits/8` bytes at `byteOffset`. */
export const encodeWord = (
  bytes: Uint8Array,
  byteOffset: number,
  wordBits: number,
  order: SpeckByteOrder,
  word: number,
): void => {
  const wb = wordBits / 8;
  // Mask to wordBits before encoding so callers can pass an unmasked compute
  // value and still get clean serialization.
  const mask = wordBits === 32 ? 0xffffffff : (1 << wordBits) - 1;
  let w = word & mask;
  if (order === "be-paper") {
    for (let i = wb - 1; i >= 0; i--) {
      bytes[byteOffset + i] = w & 0xff;
      w >>>= 8;
    }
  } else {
    for (let i = 0; i < wb; i++) {
      bytes[byteOffset + i] = w & 0xff;
      w >>>= 8;
    }
  }
};

/**
 * Decode the cipher's two-word block state from a `2 * wordBits / 8`-byte
 * sequence. Returns `[x, y]` (left/upper word, right/lower word) regardless
 * of which order the bytes were laid out in — the convention is fully
 * absorbed at the codec boundary.
 *
 *   • BE-paper: bytes 0..wb are x, bytes wb..2wb are y.
 *   • LE-NSA:  bytes 0..wb are y, bytes wb..2wb are x.
 *     (Following the NSA reference's `Plaintext: c0=y, c1=x` indexing.)
 */
export const decodeBlock = (
  bytes: Uint8Array,
  wordBits: number,
  order: SpeckByteOrder,
): [number, number] => {
  const wb = wordBits / 8;
  if (order === "be-paper") {
    return [decodeWord(bytes, 0, wordBits, order), decodeWord(bytes, wb, wordBits, order)];
  }
  // LE-NSA: y is first in memory, x is second.
  return [decodeWord(bytes, wb, wordBits, order), decodeWord(bytes, 0, wordBits, order)];
};

/** Encode a two-word block `(x, y)` into a `2 * wordBits / 8`-byte buffer. */
export const encodeBlock = (
  wordBits: number,
  order: SpeckByteOrder,
  x: number,
  y: number,
): Uint8Array => {
  const wb = wordBits / 8;
  const out = new Uint8Array(2 * wb);
  if (order === "be-paper") {
    encodeWord(out, 0, wordBits, order, x);
    encodeWord(out, wb, wordBits, order, y);
  } else {
    // LE: y first in memory.
    encodeWord(out, 0, wordBits, order, y);
    encodeWord(out, wb, wordBits, order, x);
  }
  return out;
};

/**
 * Decode all `m` key words from the master-key bytes. Returns
 * `[k_0, l_0, l_1, …, l_{m-2}]` regardless of convention; the in-memory
 * order is convention-dependent and absorbed here.
 */
export const decodeKey = (
  keyBytes: Uint8Array,
  m: number,
  wordBits: number,
  order: SpeckByteOrder,
): number[] => {
  const wb = wordBits / 8;
  const words = new Array<number>(m);
  if (order === "be-paper") {
    // BE-paper: bytes are (l_{m-2}, …, l_0, k_0) in memory.
    // index in memory order: 0 → l_{m-2}, 1 → l_{m-3}, …, m-2 → l_0, m-1 → k_0.
    // Map back to logical `words` array `[k_0, l_0, …, l_{m-2}]`.
    for (let memIdx = 0; memIdx < m; memIdx++) {
      const w = decodeWord(keyBytes, memIdx * wb, wordBits, order);
      const logicalIdx = m - 1 - memIdx; // memIdx=0 → l_{m-2} → logicalIdx=m-1
      words[logicalIdx] = w;
    }
  } else {
    // LE-NSA: bytes are (k_0, l_0, …, l_{m-2}) in memory; trivial mapping.
    for (let i = 0; i < m; i++) {
      words[i] = decodeWord(keyBytes, i * wb, wordBits, order);
    }
  }
  return words;
};

/** Validate and read the `byteOrder` param value off a step's params blob. */
export const readByteOrder = (params: Json, stepName: string): SpeckByteOrder => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error(`${stepName} requires object params`);
  }
  const v = (params as { byteOrder?: unknown }).byteOrder;
  if (v === "be-paper" || v === "le-nsa") return v;
  throw new Error(`${stepName}: byteOrder must be "be-paper" or "le-nsa", got ${String(v)}`);
};
