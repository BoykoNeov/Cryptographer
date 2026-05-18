/**
 * Serpent key-schedule simulator. Pure pedagogy-only re-implementation of
 * Anderson/Biham/Knudsen 1998 §2 that *yields* per-stage decomposition
 * alongside the round-key bytes.
 *
 * Mirrors `src/steps/serpent-key-expansion.ts`'s algorithm:
 *
 *   1. Pad master key to 256 bits (single 0x01 byte at position after the
 *      last key byte; rest zero). 256-bit keys are unchanged.
 *   2. Decode 32-byte padded buffer as 8 little-endian 32-bit prekey words
 *      `w[-8] .. w[-1]`.
 *   3. Generate `w[0] .. w[131]` via:
 *        w_i = ROL11(w_{i-8} XOR w_{i-5} XOR w_{i-3} XOR w_{i-1} XOR phi XOR i)
 *      where phi = 0x9e3779b9 (golden ratio fractional part).
 *   4. Apply bitsliced 4-bit S-boxes to 33 groups of 4 prekeys. Group `i`
 *      uses S_{(35 - i) mod 8}, walking down through the S-box list with
 *      wraparound (off-by-one trap acknowledged inline).
 *   5. Apply the Initial Permutation to each raw round key so it lines up
 *      bit-for-bit with the IP'd state inside the round body.
 *
 * Phase 2 of the linear-mode pedagogy plan
 * (~/.claude/plans/immutable-doodling-quokka.md). Same Option-B
 * re-simulate-in-viz trade-off as the AES sim — keeps the executor
 * contract unchanged at the cost of duplicating the algorithm; the
 * parity test pins both implementations to the same byte output.
 */

import { SERPENT_IP, SERPENT_PHI, SERPENT_SBOXES } from "@/ciphers/serpent-constants";
import {
  applyBitPermutation,
  readWordLE32,
  rotl32,
  sboxBitslice4,
  wordsToBytes4,
} from "@/steps/serpent-bit-ops";

/**
 * One discrete transformation step in the Serpent key schedule. Variants
 * mirror the algorithm phases above; the UI dispatches on `kind` to pick
 * the per-stage view.
 */
export type SerpentStage =
  | {
      // Phase 1: pad the master key. For 256-bit keys this is a no-op
      // (padded === masterKey extended to 32 bytes); for shorter keys
      // a single 0x01 byte lands at `masterKey.length` and the rest is
      // zeros. UI surfaces the "1 bit marker" annotation when applicable.
      readonly kind: "pad";
      readonly masterKey: Uint8Array;
      readonly padded: Uint8Array;
      /** Index of the 0x01 padding byte; -1 when no padding fired. */
      readonly padByteIndex: number;
    }
  | {
      // Phase 2: decode 32 bytes → 8 little-endian 32-bit prekey words
      // (stored conceptually at indices -8..-1; here in `prekeys` array
      // at indices 0..7 with the array-index-to-w-index offset of -8).
      readonly kind: "prekey-init";
      readonly padded: Uint8Array;
      readonly prekeys: readonly [number, number, number, number, number, number, number, number];
    }
  | {
      // Phase 3, one per j in 0..131: a single prekey-recurrence step.
      // The five inputs (w_{j-8}, w_{j-5}, w_{j-3}, w_{j-1}, phi, j) XOR
      // together, then ROL11. Counter `j` is the j value (NOT the array
      // index, which is `j + 8`).
      readonly kind: "prekey-recurrence";
      readonly j: number;
      readonly wMinus8: number;
      readonly wMinus5: number;
      readonly wMinus3: number;
      readonly wMinus1: number;
      readonly phi: number;
      readonly xorResult: number;
      readonly output: number;
    }
  | {
      // Phase 4, one per group i in 0..32: bitsliced 4-bit S-box across
      // four input prekey words → four output words. The `sboxIndex` is
      // `(35 - i) mod 8` — the trap-prone walks-down-with-wraparound.
      readonly kind: "sbox-group";
      readonly groupIndex: number;
      readonly sboxIndex: number;
      readonly sbox: readonly number[];
      readonly inputWords: readonly [number, number, number, number];
      readonly outputWords: readonly [number, number, number, number];
    }
  | {
      // Phase 5, one per group i: apply IP to the raw 16-byte round key
      // (just packed from the sbox-group output) to produce the final
      // K_i that the round body actually consumes. The raw and permuted
      // forms are both exposed so the UI can render the bit-shuffle
      // visually.
      readonly kind: "ip";
      readonly groupIndex: number;
      readonly rawRoundKey: Uint8Array;
      readonly permutedRoundKey: Uint8Array;
    };

export type SerpentScheduleTrace = {
  /** Length of the master key used. 16, 24, or 32. */
  readonly keyByteLength: 16 | 24 | 32;
  readonly stages: readonly SerpentStage[];
  /** 33 round keys (K_0..K_32), each 16 bytes. Final IP'd values. */
  readonly roundKeys: readonly Uint8Array[];
};

/**
 * Run the Serpent key schedule yielding per-stage decomposition.
 *
 * Throws on invalid `masterKey` length (must be 16, 24, or 32 bytes).
 * Matches the executor's validation envelope and produces byte-identical
 * round keys for any accepted input. Pinned by
 * `tests/serpent-key-schedule-sim-parity.test.ts`.
 */
export const simulateSerpentKeySchedule = (masterKey: Uint8Array): SerpentScheduleTrace => {
  if (masterKey.length !== 16 && masterKey.length !== 24 && masterKey.length !== 32) {
    throw new Error(
      `simulateSerpentKeySchedule: master key must be 16, 24, or 32 bytes; got ${masterKey.length}`,
    );
  }
  const keyByteLength = masterKey.length as 16 | 24 | 32;

  const stages: SerpentStage[] = [];

  // ─── Stage 1: pad to 32 bytes ──────────────────────────────────────
  const padded = new Uint8Array(32);
  padded.set(masterKey);
  let padByteIndex = -1;
  if (masterKey.length < 32) {
    padded[masterKey.length] = 0x01;
    padByteIndex = masterKey.length;
  }
  stages.push({ kind: "pad", masterKey: new Uint8Array(masterKey), padded, padByteIndex });

  // ─── Stage 2: 8 prekey words from padded ───────────────────────────
  const TOTAL_PREKEYS = 140; // w[-8..-1] + w[0..131] = 8 + 132 = 140
  const prekey = new Array<number>(TOTAL_PREKEYS);
  for (let j = 0; j < 8; j++) {
    prekey[j] = readWordLE32(padded, j * 4);
  }
  stages.push({
    kind: "prekey-init",
    padded,
    prekeys: [
      prekey[0] ?? 0,
      prekey[1] ?? 0,
      prekey[2] ?? 0,
      prekey[3] ?? 0,
      prekey[4] ?? 0,
      prekey[5] ?? 0,
      prekey[6] ?? 0,
      prekey[7] ?? 0,
    ],
  });

  // ─── Stage 3: w[0] .. w[131] via 5-input XOR + ROL11 ───────────────
  // Array index `idx = j + 8` since w[-8..-1] occupy 0..7.
  for (let j = 0; j < 132; j++) {
    const idx = j + 8;
    const w8 = prekey[idx - 8] ?? 0;
    const w5 = prekey[idx - 5] ?? 0;
    const w3 = prekey[idx - 3] ?? 0;
    const w1 = prekey[idx - 1] ?? 0;
    const x = (w8 ^ w5 ^ w3 ^ w1 ^ SERPENT_PHI ^ j) >>> 0;
    const out = rotl32(x, 11);
    prekey[idx] = out;
    stages.push({
      kind: "prekey-recurrence",
      j,
      wMinus8: w8,
      wMinus5: w5,
      wMinus3: w3,
      wMinus1: w1,
      phi: SERPENT_PHI,
      xorResult: x,
      output: out,
    });
  }

  // ─── Stages 4 + 5: bitsliced S-box + IP per round key ──────────────
  const roundKeys: Uint8Array[] = [];
  for (let i = 0; i < 33; i++) {
    // S-box index: walks down with wraparound. (35 - i) % 8 for i in
    // 0..32. Double-mod handles the negative-remainder edge defensively
    // (35 - i is always non-negative here, so this is paranoia, but the
    // executor does the same and we mirror it byte-identically).
    const sboxIdx = (((35 - i) % 8) + 8) % 8;
    const sbox = SERPENT_SBOXES[sboxIdx] ?? [];

    const base = 8 + 4 * i;
    const w0 = prekey[base] ?? 0;
    const w1 = prekey[base + 1] ?? 0;
    const w2 = prekey[base + 2] ?? 0;
    const w3 = prekey[base + 3] ?? 0;
    const [k0, k1, k2, k3] = sboxBitslice4(w0, w1, w2, w3, sbox);
    stages.push({
      kind: "sbox-group",
      groupIndex: i,
      sboxIndex: sboxIdx,
      sbox,
      inputWords: [w0, w1, w2, w3],
      outputWords: [k0, k1, k2, k3],
    });

    const rawRoundKey = wordsToBytes4(k0, k1, k2, k3);
    const permutedRoundKey = applyBitPermutation(rawRoundKey, SERPENT_IP);
    stages.push({
      kind: "ip",
      groupIndex: i,
      rawRoundKey,
      permutedRoundKey,
    });
    roundKeys.push(permutedRoundKey);
  }

  return {
    keyByteLength,
    stages,
    roundKeys,
  };
};
