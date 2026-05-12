/**
 * Shared AES round-group construction.
 *
 * Phase-1 extraction of the inline helpers from `aes-128.ts` and
 * `aes-128-decrypt.ts`. These two specs now call into here; the new
 * mode-specific spec factories (ECB/CBC/CTR coming in Phases 1–3) will
 * also call in so the multi-block AES round structure is built in
 * exactly one place.
 *
 * What the "body" means: a top-level AES spec has the shape
 *
 *     [ key-expansion, ...body ]
 *
 * where `body` is the per-block computation:
 *
 *   encrypt body:  initial-AddRoundKey, round.1..round.{N-1}, round.N (no MixColumns)
 *   decrypt body:  inv-initial-AddRoundKey(N), inv-round.{N-1}..inv-round.1, inv-round.0
 *
 * In single-block specs the body sits at the top level; in multi-block
 * mode specs it sits inside an `iterate` group so it runs per block. The
 * builder returns the body only — key-expansion is supplied separately by
 * the caller because it always runs once (not per block) regardless of mode.
 *
 * AES variant agnostic: only the round count differs across AES-128 / 192 /
 * 256 (10 / 12 / 14). The S-box, mix matrix, shift schedule, and inverse
 * tables are identical across variants per FIPS-197 §5.
 */

import type { StepNode } from "../core/types";
import {
  AES_INV_MIX_MATRIX,
  AES_INV_SBOX,
  AES_INV_SHIFT_ROWS,
  AES_MIX_MATRIX,
  AES_SBOX,
  AES_SHIFT_ROWS,
} from "./aes-constants";

// ─── Forward (encrypt) leaf factories ──────────────────────────────────────
// Fresh leaves per call: the spec tree is `readonly`, but downstream mutators
// (updateStepParams) replace specific nodes by id; sharing leaves across
// rounds would let one edit accidentally affect every round.

const subBytesStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.sub-bytes`,
  type: "generic.byte-substitution@1",
  params: { sbox: [...AES_SBOX] },
});

const shiftRowsStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.shift-rows`,
  type: "generic.shift-rows@1",
  params: { shifts: [...AES_SHIFT_ROWS] },
});

const mixColumnsStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.mix-columns`,
  type: "generic.mix-columns@1",
  params: { matrix: AES_MIX_MATRIX.map((row) => [...row]) },
});

const addRoundKeyStep = (idPrefix: string, roundIndex: number): StepNode => ({
  kind: "step",
  id: `${idPrefix}.add-round-key`,
  type: "generic.add-round-key@1",
  params: { auxName: `roundKey.${roundIndex}` },
});

const encryptRound = (n: number): StepNode => ({
  kind: "group",
  id: `round.${n}`,
  label: `Round ${n}`,
  children: [
    subBytesStep(`round.${n}`),
    shiftRowsStep(`round.${n}`),
    mixColumnsStep(`round.${n}`),
    addRoundKeyStep(`round.${n}`, n),
  ],
});

const encryptFinalRound = (rounds: number): StepNode => ({
  kind: "group",
  id: `round.${rounds}`,
  label: `Round ${rounds} (final, no MixColumns)`,
  children: [
    subBytesStep(`round.${rounds}`),
    shiftRowsStep(`round.${rounds}`),
    addRoundKeyStep(`round.${rounds}`, rounds),
  ],
});

/**
 * Build the forward (encrypt) AES body for the given round count.
 * `rounds = 10` → AES-128, `12` → AES-192, `14` → AES-256.
 *
 * Result shape: `[ initial-AddRoundKey, round.1, …, round.{rounds-1}, round.{rounds}(final) ]`.
 */
export function buildAesEncryptBody(rounds: number): readonly StepNode[] {
  return [
    addRoundKeyStep("initial", 0),
    ...Array.from({ length: rounds - 1 }, (_, i) => encryptRound(i + 1)),
    encryptFinalRound(rounds),
  ];
}

// ─── Inverse (decrypt) leaf factories ──────────────────────────────────────

const invSubBytesStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-sub-bytes`,
  type: "generic.byte-substitution@1",
  // Same executor as forward SubBytes; only the table differs. Proof that
  // the registry abstraction holds — no special "inverse SubBytes" type.
  params: { sbox: [...AES_INV_SBOX] },
});

const invShiftRowsStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-shift-rows`,
  type: "generic.shift-rows@1",
  // shifts=[0,3,2,1]: shifting LEFT by these amounts equals shifting RIGHT
  // by [0,1,2,3], inverting the forward shift schedule.
  params: { shifts: [...AES_INV_SHIFT_ROWS] },
});

const invMixColumnsStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-mix-columns`,
  type: "generic.mix-columns@1",
  params: { matrix: AES_INV_MIX_MATRIX.map((row) => [...row]) },
});

const decryptRound = (n: number): StepNode => ({
  kind: "group",
  id: `inv-round.${n}`,
  label: `Inverse Round ${n}`,
  // FIPS-197 §5.3 inverse round body. AddRoundKey BEFORE InvMixColumns is
  // intrinsic to AES — cannot be hidden behind a "reverse the order"
  // abstraction.
  children: [
    invShiftRowsStep(`inv-round.${n}`),
    invSubBytesStep(`inv-round.${n}`),
    addRoundKeyStep(`inv-round.${n}`, n),
    invMixColumnsStep(`inv-round.${n}`),
  ],
});

const decryptFinalRound: StepNode = {
  kind: "group",
  id: "inv-round.0",
  label: "Inverse Round 0 (no InvMixColumns)",
  children: [
    invShiftRowsStep("inv-round.0"),
    invSubBytesStep("inv-round.0"),
    addRoundKeyStep("inv-round.0", 0),
  ],
};

/**
 * Build the inverse (decrypt) AES body for the given round count.
 * Round keys consumed in reverse: initial AddRoundKey uses roundKey.{rounds},
 * then inverse rounds {rounds-1}..1, then the final inverse round at 0.
 *
 * Result shape: `[ inv-initial-AddRoundKey(rounds), inv-round.{rounds-1}, …, inv-round.1, inv-round.0(final) ]`.
 */
export function buildAesDecryptBody(rounds: number): readonly StepNode[] {
  return [
    addRoundKeyStep("inv-initial", rounds),
    ...Array.from({ length: rounds - 1 }, (_, i) => decryptRound(rounds - 1 - i)),
    decryptFinalRound,
  ];
}
