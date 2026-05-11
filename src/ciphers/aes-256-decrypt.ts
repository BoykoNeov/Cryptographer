/**
 * AES-256 decryption (inverse cipher), FIPS-197 §5.3.
 *
 * Mirror of `aes-128-decrypt.ts` and `aes-192-decrypt.ts`. ROUNDS=14, 32-byte
 * key. Key expansion is shared with the forward AES-256 spec — uses the
 * FORWARD S-box and the AES-256-only `i%Nk==4` SubWord branch even when
 * decrypting (the inverse cipher consumes the same round keys in reverse,
 * never re-derives them).
 */

import type { CipherSpec, StepNode } from "../core/types";
import {
  AES_INV_MIX_MATRIX,
  AES_INV_SBOX,
  AES_INV_SHIFT_ROWS,
  AES_RCON,
  AES_SBOX,
} from "./aes-constants";

const ROUNDS = 14;

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

export const aes256DecryptSpec: CipherSpec = {
  id: "aes-256-decrypt@1",
  name: "AES-256 (decrypt)",
  stateShape: "matrix4x4-bytes",
  inputs: {
    plaintext: { shape: "matrix4x4-bytes" },
    key: { byteLength: 32 },
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
