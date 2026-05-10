/**
 * AES-128 decryption (inverse cipher), FIPS-197 §5.3.
 *
 * This file is a load-bearing test of the modularity claim: the inverse
 * cipher uses the EXACT SAME step-type registry as the forward cipher.
 * No new executors, no special cases. The only differences are:
 *   1. Round structure runs "outward": initial AddRoundKey at round 10,
 *      then rounds 9..1, then a final round at round 0.
 *   2. Inside each round, the order is InvShiftRows → InvSubBytes →
 *      AddRoundKey → InvMixColumns (note: AddRoundKey BEFORE InvMixColumns,
 *      unlike forward). Final round drops the InvMixColumns.
 *   3. Step params use the inverse S-box, inverse MixColumns matrix, and
 *      shifts = [0, 3, 2, 1] (= shifting RIGHT by [0, 1, 2, 3]).
 *   4. Key expansion is identical to forward — same round keys, just read
 *      back in reverse order via the AddRoundKey aux references.
 */

import type { CipherSpec, StepNode } from "../core/types";
import {
  AES_INV_MIX_MATRIX,
  AES_INV_SBOX,
  AES_INV_SHIFT_ROWS,
  AES_RCON,
  AES_SBOX,
} from "./aes-constants";

const ROUNDS = 10;

// ─── Step factories (each returns a fresh leaf per call) ──────────────────
// Why fresh per call: the spec tree is `readonly`, but downstream mutation
// helpers (updateStepParams) replace specific nodes by id. Sharing leaves
// across rounds would let one update accidentally affect every round.

const invSubBytesStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-sub-bytes`,
  type: "generic.byte-substitution@1",
  // Param is the *inverse* S-box; the substitution executor itself is the
  // same one used by forward SubBytes — proof that the abstraction holds.
  params: { sbox: [...AES_INV_SBOX] },
});

const invShiftRowsStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-shift-rows`,
  type: "generic.shift-rows@1",
  // shifts=[0,3,2,1]: shifting LEFT by these amounts equals shifting RIGHT
  // by [0,1,2,3], which is the inverse of forward AES's left-shift schedule.
  params: { shifts: [...AES_INV_SHIFT_ROWS] },
});

const invMixColumnsStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-mix-columns`,
  type: "generic.mix-columns@1",
  params: { matrix: AES_INV_MIX_MATRIX.map((row) => [...row]) },
});

const addRoundKeyStep = (idPrefix: string, roundIndex: number): StepNode => ({
  kind: "step",
  id: `${idPrefix}.add-round-key`,
  type: "generic.add-round-key@1",
  // Reads aux key "roundKey.{n}" — same names key-expansion writes during
  // forward, so we share that step verbatim.
  params: { auxName: `roundKey.${roundIndex}` },
});

// ─── Round assembly ───────────────────────────────────────────────────────
// FIPS-197 §5.3 inverse round body. Note the AddRoundKey-before-MixColumns
// asymmetry vs the forward cipher — this is intrinsic to AES and cannot be
// hidden behind a "reverse the order" abstraction.

const invRound = (n: number): StepNode => ({
  kind: "group",
  id: `inv-round.${n}`,
  label: `Inverse Round ${n}`,
  children: [
    invShiftRowsStep(`inv-round.${n}`),
    invSubBytesStep(`inv-round.${n}`),
    addRoundKeyStep(`inv-round.${n}`, n),
    invMixColumnsStep(`inv-round.${n}`),
  ],
});

// Final round of decryption: same shape as forward final round, just with
// inverse S-box and inverse shift schedule, ending with roundKey.0.
const invFinalRound: StepNode = {
  kind: "group",
  id: "inv-round.0",
  label: "Inverse Round 0 (no InvMixColumns)",
  children: [
    invShiftRowsStep("inv-round.0"),
    invSubBytesStep("inv-round.0"),
    addRoundKeyStep("inv-round.0", 0),
  ],
};

// ─── Full spec ────────────────────────────────────────────────────────────

export const aes128DecryptSpec: CipherSpec = {
  id: "aes-128-decrypt@1",
  name: "AES-128 (decrypt)",
  stateShape: "matrix4x4-bytes",
  inputs: {
    plaintext: { shape: "matrix4x4-bytes" },
    key: { byteLength: 16 },
  },
  steps: [
    // Step 1: derive round keys from the user-provided key. Identical to
    // forward — uses the FORWARD S-box (key expansion uses SubWord, which
    // applies the forward S-box even when we're decrypting).
    {
      kind: "step",
      id: "key-expansion",
      type: "aes.key-expansion@1",
      params: {
        keyAuxName: "key",
        outputPrefix: "roundKey",
        sbox: [...AES_SBOX],
        rcon: [...AES_RCON],
        rounds: ROUNDS,
      },
    },

    // Step 2: initial AddRoundKey with the LAST round key.
    addRoundKeyStep("inv-initial", ROUNDS),

    // Steps 3..N-1: inverse rounds 9..1.
    ...Array.from({ length: ROUNDS - 1 }, (_, i) => invRound(ROUNDS - 1 - i)),

    // Step N: final inverse round (no InvMixColumns), ends with roundKey.0.
    invFinalRound,
  ],
};
