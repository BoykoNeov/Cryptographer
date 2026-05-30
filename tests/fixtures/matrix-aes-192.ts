/**
 * Shared test fixture — the legacy **matrix** AES-192 spec.
 *
 * Scaffolding-suppression Slice B1.3 (2026-05-29) converted every shipped
 * single-block AES spec (128/192/256, both directions) to byte-native
 * port-native primitives, so there is no longer a single-block matrix AES
 * spec in `src/ciphers/`. A handful of tests, however, are *about* the legacy
 * matrix machinery itself, not about AES the cipher:
 *
 *   - `tests/provenance-hover-integration.test.tsx` — MatrixView cell-level
 *     provenance hover, which is a `matrix4x4-bytes` `stateAfter` feature.
 *   - `tests/port-projection-q-gate-9.test.ts` — the Phase-0 lifted-legacy
 *     projection round-trip, which is defined over `generic.*` matrix frames.
 *   - `tests/aux-graph-derivation.test.ts` — synthetic endpoint-pill placement,
 *     which pins the *matrix* graph shape (a top-level aux-only `key-expansion`
 *     root, a standalone `initial.add-round-key`, a `round.12` final round, and
 *     crucially NO `$input` port-flow source node).
 *
 * This is the `frame-port-values.test.ts` `liftedLegacySubBytesSpec` precedent
 * generalized from a single leaf to the full AES-192 round structure. It is
 * hand-built from the still-registered `generic.*` lifted-legacy step types.
 * The matrix builder (`src/ciphers/aes-round-builder.ts`) lost its last
 * consumer when CBC went byte-native and was deleted in Slice B1.4b; this
 * fixture never imported it. It depends only on the `generic.*` registrations
 * + `CipherSpec` shape, so it survives until Phase C retires the matrix
 * machinery (the MatrixView/projection concepts these tests cover retire at
 * the same time).
 *
 * Structurally identical to the pre-B1.3 `src/ciphers/aes-192.ts`: Nk=6
 * (24-byte key), ROUNDS=12, matrix4x4-bytes state, `generic.byte-substitution`
 * / `generic.shift-rows` / `generic.mix-columns` / `generic.add-round-key`
 * round body, with the initial AddRoundKey as a standalone top-level step.
 */

import { AES_MIX_MATRIX, AES_RCON, AES_SBOX, AES_SHIFT_ROWS } from "@/ciphers/aes-constants";
import type { CipherSpec, StepNode } from "@/core/types";

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

/**
 * The legacy matrix AES-192 encrypt spec, frozen as a test fixture. Run it
 * under the DEFAULT (legacy) dispatch path with a `matrixFromBytes(...)`
 * initial state — it has no port-native primitives and must NOT be run with
 * `portedDispatchEnabled: true`.
 */
export const matrixAes192Spec: CipherSpec = {
  id: "matrix-aes-192-fixture@1",
  name: "AES-192 (matrix fixture)",
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
