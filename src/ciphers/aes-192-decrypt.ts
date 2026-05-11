/**
 * AES-192 decryption (inverse cipher), FIPS-197 §5.3.
 *
 * Same modularity story as `aes-128-decrypt.ts`: no new step types, no
 * special-cased executors — the inverse cipher is just the same generic
 * step registry consumed in reverse order, with inverse S-box / inverse
 * MixColumns matrix / inverse shift schedule. The differences from
 * AES-128-decrypt are ROUNDS=12 and a 24-byte key declared in `inputs`.
 *
 * Key expansion is shared with the forward AES-192 spec (uses the FORWARD
 * S-box even when decrypting — see `aes.key-expansion@1` docs).
 */

import type { CipherSpec, StepNode } from "../core/types";
import {
  AES_INV_MIX_MATRIX,
  AES_INV_SBOX,
  AES_INV_SHIFT_ROWS,
  AES_RCON,
  AES_SBOX,
} from "./aes-constants";

const ROUNDS = 12;

const invSubBytesStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-sub-bytes`,
  type: "generic.byte-substitution@1",
  params: { sbox: [...AES_INV_SBOX] },
});

const invShiftRowsStep = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-shift-rows`,
  type: "generic.shift-rows@1",
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
  params: { auxName: `roundKey.${roundIndex}` },
});

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

export const aes192DecryptSpec: CipherSpec = {
  id: "aes-192-decrypt@1",
  name: "AES-192 (decrypt)",
  stateShape: "matrix4x4-bytes",
  inputs: {
    plaintext: { shape: "matrix4x4-bytes" },
    key: { byteLength: 24 },
  },
  steps: [
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
    addRoundKeyStep("inv-initial", ROUNDS),
    ...Array.from({ length: ROUNDS - 1 }, (_, i) => invRound(ROUNDS - 1 - i)),
    invFinalRound,
  ],
};
