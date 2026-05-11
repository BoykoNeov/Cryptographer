/**
 * AES-192 encryption spec, FIPS-197 §5.1.
 *
 * Structurally identical to AES-128: same step types, same MixColumn matrix,
 * same S-box. The only differences are Nk=6 (24-byte cipher key) and
 * ROUNDS=12 (vs 10 / Nk=4 for AES-128). The shared `aes.key-expansion@1`
 * executor derives Nk from the actual key length at runtime; this file
 * just tells the runtime to expect a 24-byte key and to assemble 12 rounds.
 *
 * Constructed off the same step factories as `aes-128.ts` — kept as a
 * separate file (rather than parameterizing aes-128) so each variant has
 * a discoverable, named CipherSpec the UI/registry can pick by id.
 */

import type { CipherSpec, StepNode } from "../core/types";
import { AES_MIX_MATRIX, AES_RCON, AES_SBOX, AES_SHIFT_ROWS } from "./aes-constants";

const ROUNDS = 12;

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

const round = (n: number): StepNode => ({
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

const finalRound: StepNode = {
  kind: "group",
  id: `round.${ROUNDS}`,
  label: `Round ${ROUNDS} (final, no MixColumns)`,
  children: [
    subBytesStep(`round.${ROUNDS}`),
    shiftRowsStep(`round.${ROUNDS}`),
    addRoundKeyStep(`round.${ROUNDS}`, ROUNDS),
  ],
};

export const aes192Spec: CipherSpec = {
  id: "aes-192@1",
  name: "AES-192",
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
    addRoundKeyStep("initial", 0),
    ...Array.from({ length: ROUNDS - 1 }, (_, i) => round(i + 1)),
    finalRound,
  ],
};
