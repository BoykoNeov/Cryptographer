/**
 * DES key-schedule simulator. Pure pedagogy-only re-implementation of
 * FIPS 46-3 §5 (Key Schedule Calculation) that *yields* the per-round
 * decomposition: cumulative shift count, C_i (28 bits), D_i (28 bits),
 * K_i (48 bits = 6 bytes).
 *
 * Why this exists separately from `src/steps/des-key-schedule.ts`: the
 * executor's contract is `(state, params, ctx) → state`, so it can only
 * write the final 16 round-key buffers (each 6 bytes) to aux. The
 * intermediate C_i / D_i halves — the part that makes the schedule
 * pedagogically interesting (rotation by 1 or 2 bits per round, total of
 * 28 bits rotated across 16 rounds = full cycle) — are invisible to the
 * trace. This file re-runs the algorithm and yields those intermediates
 * so the UI can step through per-round.
 *
 * Architectural cost: re-simulating in viz duplicates the algorithm
 * logic. The parity test (`tests/des-key-schedule-sim-parity.test.ts`)
 * pins the simulator's `roundKeys` byte-for-byte against the executor's
 * `auxWrites`, catching any drift between the two copies. Same trade-off
 * as AES (`src/ui/key-schedule-sim/aes.ts`) and Serpent.
 *
 * Implementation re-uses the same bit-level helpers the executor uses
 * (`src/steps/des-bit-ops.ts`) — FIPS-bit-numbering, rotate-left,
 * permute. Keeping the helpers shared rather than duplicated reduces the
 * surface area where the simulator could drift from the executor.
 */

import { bitsToFipsBytes, fipsBytesToBits, fipsPermute, rotateBitsLeft } from "@/steps/des-bit-ops";

/**
 * One round's intermediate values. Bit arrays are MSB-first to match the
 * FIPS convention used throughout the executor + oracle. The packed byte
 * forms (`Cbytes` / `Dbytes` / `K`) are convenience for the UI's
 * `<ByteRow>` consumer — same bits, just packed to bytes via
 * `bitsToFipsBytes`.
 */
export type DesScheduleRound = {
  /** 1-based round index, matching FIPS notation. */
  readonly round: number;
  /** This round's per-round shift count (1 or 2). */
  readonly shift: number;
  /** Cumulative shift count from round 1 through this round. */
  readonly cumulativeShift: number;
  /** C_i (28-bit left half) as a bit array of length 28. */
  readonly Cbits: readonly number[];
  /** D_i (28-bit right half) as a bit array of length 28. */
  readonly Dbits: readonly number[];
  /** C_i packed MSB-first into 4 bytes (the final 4 bits of byte 3 are 0). */
  readonly Cbytes: Uint8Array;
  /** D_i packed MSB-first into 4 bytes (the final 4 bits of byte 3 are 0). */
  readonly Dbytes: Uint8Array;
  /** K_i = PC-2(C_i || D_i), 48 bits packed MSB-first into 6 bytes. */
  readonly K: Uint8Array;
};

export type DesScheduleTrace = {
  /** C_0 — the master key after PC-1 then split into two 28-bit halves. */
  readonly C0bits: readonly number[];
  readonly D0bits: readonly number[];
  readonly rounds: readonly DesScheduleRound[];
  /** Same as `rounds[i].K`; surfaced for symmetry with AES/Serpent traces.
   *  The parity test asserts this equals the executor's `roundKey.{i}` aux
   *  byte-for-byte. */
  readonly roundKeys: readonly Uint8Array[];
};

export type DesSimParams = {
  readonly pc1: readonly number[];
  readonly pc2: readonly number[];
  readonly shifts: readonly number[];
};

/**
 * Run the full DES key schedule yielding per-round decomposition. Throws
 * on invalid input (non-8-byte master key, missing shift, wrong table
 * length) — matches the executor's validation envelope so a simulator
 * exception always signals "something at the spec layer is wrong," not
 * a divergence between simulator and executor.
 */
export const simulateDesKeySchedule = (
  masterKey: Uint8Array,
  params: DesSimParams,
): DesScheduleTrace => {
  if (masterKey.length !== 8) {
    throw new Error(`simulateDesKeySchedule: master key must be 8 bytes; got ${masterKey.length}`);
  }
  if (params.pc1.length !== 56) {
    throw new Error(`simulateDesKeySchedule: PC-1 must have 56 entries; got ${params.pc1.length}`);
  }
  if (params.pc2.length !== 48) {
    throw new Error(`simulateDesKeySchedule: PC-2 must have 48 entries; got ${params.pc2.length}`);
  }
  if (params.shifts.length !== 16) {
    throw new Error(
      `simulateDesKeySchedule: shifts must have 16 entries; got ${params.shifts.length}`,
    );
  }

  // PC-1 drops the 8 parity bits, leaving 56. Result packs into 7 bytes
  // with one trailing 0 bit in byte 6.
  const cd = fipsPermute(masterKey, params.pc1, 56);
  const cdBits = fipsBytesToBits(cd, 56);
  const C0bits = cdBits.slice(0, 28);
  const D0bits = cdBits.slice(28, 56);

  let C = C0bits.slice();
  let D = D0bits.slice();
  let cumulativeShift = 0;

  const rounds: DesScheduleRound[] = [];
  const roundKeys: Uint8Array[] = [];

  for (let r = 0; r < 16; r++) {
    const shift = params.shifts[r];
    if (shift === undefined) {
      throw new Error(`simulateDesKeySchedule: shifts[${r}] missing`);
    }
    C = rotateBitsLeft(C, shift, 28);
    D = rotateBitsLeft(D, shift, 28);
    cumulativeShift += shift;
    // Pack C || D back into 7 bytes for PC-2.
    const cdConcat = bitsToFipsBytes([...C, ...D]);
    const K = fipsPermute(cdConcat, params.pc2, 48);
    // For UI: pack C / D as 4 bytes each. Cbits/Dbits is 28 bits → packs
    // into 4 bytes with the final 4 bits zero. (Slicing into 7 bytes
    // would split byte 3 into "high 4 bits of C, low 4 bits of D"; the
    // 4-byte each form keeps the halves cleanly separable for display.)
    const Cbytes = bitsToFipsBytes(C);
    const Dbytes = bitsToFipsBytes(D);
    rounds.push({
      round: r + 1,
      shift,
      cumulativeShift,
      Cbits: C.slice(),
      Dbits: D.slice(),
      Cbytes,
      Dbytes,
      K,
    });
    roundKeys.push(K);
  }

  return {
    C0bits,
    D0bits,
    rounds,
    roundKeys,
  };
};
