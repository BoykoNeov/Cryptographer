/**
 * Shared test fixture — the legacy **matrix** AES-128 ECB spec (aux-mode
 * `iterate`).
 *
 * Scaffolding-suppression Slice B1.4a converted the shipped AES ECB spec to a
 * byte-native **port-mode** iterate (`seedInput`/`blockByteLength`/`bodyOutput`,
 * no `split-blocks`/`compute-block-count`/`concat-blocks`). But several tests
 * are *about the legacy aux-mode iterate machinery itself* — the
 * `blocksFromAux` / `outBlocksAux` block-chip value resolution
 * (`lookupEdgeValue`), the `split-blocks → iterate → concat-blocks` aux-edge
 * synthesis, and the aux-only-root spine-edge suppression — not about AES the
 * cipher. That machinery is still live for the matrix AES-128 **CBC** spec
 * until Slice B1.4b, so it is genuinely covered, not dead.
 *
 * This is the multi-block analogue of `tests/fixtures/matrix-aes-192.ts`:
 * hand-built from the still-registered `generic.*` lifted-legacy step types
 * plus the `generic.{split,concat}-blocks@1` / `generic.compute-block-count@1`
 * mode-boundary steps. The matrix body builder (`aes-round-builder.ts`) was
 * deleted in B1.4b, so this fixture inlines its own `generic.*` round nodes
 * (it never imported it). It depends only on the `generic.*` registrations +
 * `CipherSpec` shape, so it survives until Phase C retires the matrix +
 * aux-mode-iterate machinery.
 *
 * Structurally identical to the pre-B1.4a `src/ciphers/aes-128-ecb.ts`:
 * `stateShape: "bytes"`, key-expansion + split-blocks + compute-block-count
 * before the aux-mode iterate (`countFromAux`/`blocksFromAux`/`outBlocksAux`),
 * a matrix `generic.*` round body inside it (with the initial AddRoundKey as
 * the iterate body's first child), and concat-blocks after. Run it under the
 * DEFAULT (legacy) dispatch path — it has no port-native primitives and must
 * NOT be run with `portedDispatchEnabled: true`.
 */

import { AES_MIX_MATRIX, AES_RCON, AES_SBOX, AES_SHIFT_ROWS } from "@/ciphers/aes-constants";
import type { CipherSpec, StepNode } from "@/core/types";

const ROUNDS = 10;
const BLOCK_SIZE = 16;

// Aux key names — must match between split-blocks / iterate / concat-blocks
// (the same names the pre-B1.4a matrix `aes-ecb-builder.ts` used).
const AUX_INPUT_BLOCKS = "input-blocks";
const AUX_OUTPUT_BLOCKS = "output-blocks";
const AUX_BLOCK_COUNT = "blockCount";

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

// The per-block matrix AES body: initial AddRoundKey + 9 full rounds + final.
const iterateBody: StepNode[] = [
  addRoundKeyStep("initial", 0),
  ...Array.from({ length: ROUNDS - 1 }, (_, i) => round(i + 1)),
  finalRound,
];

/**
 * The legacy matrix AES-128 ECB encrypt spec, frozen as a test fixture. Run it
 * under the DEFAULT (legacy) dispatch path with a `makeBytesState(...)` initial
 * state and `aux["key"]` seeded; it has no port-native primitives and must NOT
 * be run with `portedDispatchEnabled: true`.
 */
export const matrixAesEcbSpec: CipherSpec = {
  id: "matrix-aes-128-ecb-fixture@1",
  name: "AES-128 ECB (matrix fixture)",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 16 },
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
    {
      kind: "step",
      id: "split-blocks",
      type: "generic.split-blocks@1",
      params: { blockSize: BLOCK_SIZE, outBlocksAux: AUX_INPUT_BLOCKS },
    },
    {
      kind: "step",
      id: "compute-block-count",
      type: "generic.compute-block-count@1",
      params: { blockSize: BLOCK_SIZE, countAux: AUX_BLOCK_COUNT },
    },
    {
      kind: "iterate",
      id: "ecb-blocks",
      label: "ECB blocks (per-block AES)",
      countFromAux: AUX_BLOCK_COUNT,
      blocksFromAux: AUX_INPUT_BLOCKS,
      outBlocksAux: AUX_OUTPUT_BLOCKS,
      children: iterateBody,
    },
    {
      kind: "step",
      id: "concat-blocks",
      type: "generic.concat-blocks@1",
      params: { blocksAux: AUX_OUTPUT_BLOCKS },
    },
  ],
};
