/**
 * Shared factory for the AES-ECB (Electronic Codebook) multi-block specs.
 *
 * ECB is the simplest cipher mode — encrypt each block independently, no
 * chaining, no IV. Famous as the "what NOT to do" mode: identical
 * plaintext blocks produce identical ciphertext blocks, leaking structure
 * (the Tux-image leak). We ship it because that leak is the pedagogical
 * setup for understanding why CBC and CTR exist.
 *
 * Spec shape (encrypt):
 *
 *   [
 *     key-expansion (writes roundKey.0..N to aux; state passthrough)
 *     split-blocks (writes input-blocks: MatrixState[] to aux; state passthrough)
 *     compute-block-count (writes blockCount: number to aux)
 *     iterate (count=blockCount, blocks=input-blocks, out=output-blocks) {
 *       initial AddRoundKey
 *       round.1..N-1
 *       round.N (no MixColumns)
 *     }
 *     concat-blocks (reads output-blocks → final BytesState)
 *   ]
 *
 * Decrypt is structurally identical with `buildAesDecryptBody` swapped in.
 *
 * Padding is layered on top by `applyPaddingScheme` (the encrypt spec gets
 * a `pkcs7-pad` prepended; the decrypt spec gets a `pkcs7-unpad`
 * appended). The unpadded spec is itself a valid cipher only when the
 * input length is already a multiple of 16 — that's what `split-blocks`
 * checks for.
 *
 * Variant-aware (AES-128/192/256). Today Phase 1 only ships AES-128 specs
 * (see `aes-128-ecb.ts`, `aes-128-ecb-decrypt.ts`), but the rest of the
 * grid is one-liner specs away when Phase 4 lands.
 */

import type { CipherSpec, StepNode } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import { buildAesDecryptBody, buildAesEncryptBody } from "./aes-round-builder";

export type AesVariant = "aes-128" | "aes-192" | "aes-256";
export type CipherDirection = "encrypt" | "decrypt";

const ROUNDS_BY_VARIANT: Readonly<Record<AesVariant, number>> = {
  "aes-128": 10,
  "aes-192": 12,
  "aes-256": 14,
};

const KEY_BYTES_BY_VARIANT: Readonly<Record<AesVariant, number>> = {
  "aes-128": 16,
  "aes-192": 24,
  "aes-256": 32,
};

const VARIANT_DISPLAY: Readonly<Record<AesVariant, string>> = {
  "aes-128": "AES-128",
  "aes-192": "AES-192",
  "aes-256": "AES-256",
};

// Aux keys used by the multi-block plumbing. Held in one place so the
// names match between split-blocks / iterate / concat-blocks. Direction-
// agnostic — the per-iteration input is always "input-blocks" regardless
// of whether those blocks are plaintext or ciphertext.
const AUX_INPUT_BLOCKS = "input-blocks";
const AUX_OUTPUT_BLOCKS = "output-blocks";
const AUX_BLOCK_COUNT = "blockCount";

const BLOCK_SIZE = 16;

const keyExpansionLeaf = (rounds: number): StepNode => ({
  kind: "step",
  id: "key-expansion",
  type: "aes.key-expansion@1",
  params: {
    keyAuxName: "key",
    outputPrefix: "roundKey",
    sbox: [...AES_SBOX],
    rcon: [...AES_RCON],
    rounds,
  },
});

const splitBlocksLeaf = (): StepNode => ({
  kind: "step",
  id: "split-blocks",
  type: "generic.split-blocks@1",
  params: { blockSize: BLOCK_SIZE, outBlocksAux: AUX_INPUT_BLOCKS },
});

const computeBlockCountLeaf = (): StepNode => ({
  kind: "step",
  id: "compute-block-count",
  type: "generic.compute-block-count@1",
  params: { blockSize: BLOCK_SIZE, countAux: AUX_BLOCK_COUNT },
});

const concatBlocksLeaf = (): StepNode => ({
  kind: "step",
  id: "concat-blocks",
  type: "generic.concat-blocks@1",
  params: { blocksAux: AUX_OUTPUT_BLOCKS },
});

export function buildAesEcbSpec(variant: AesVariant, direction: CipherDirection): CipherSpec {
  const rounds = ROUNDS_BY_VARIANT[variant];
  const keyBytes = KEY_BYTES_BY_VARIANT[variant];
  const body = direction === "encrypt" ? buildAesEncryptBody(rounds) : buildAesDecryptBody(rounds);

  const isDecrypt = direction === "decrypt";
  const specId = `${variant}-ecb${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${VARIANT_DISPLAY[variant]} ECB${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: "ecb-blocks",
    label: "ECB blocks (per-block AES)",
    countFromAux: AUX_BLOCK_COUNT,
    blocksFromAux: AUX_INPUT_BLOCKS,
    outBlocksAux: AUX_OUTPUT_BLOCKS,
    children: body,
  };

  return {
    id: specId,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: keyBytes },
    },
    steps: [
      // Key expansion runs once total — outside the per-block loop. State
      // passes through unchanged (the executor only writes to aux).
      keyExpansionLeaf(rounds),
      // Boundary: BytesState → MatrixState[] in aux. State stays a
      // BytesState passthrough so the next step (count) can read its
      // length without inspecting aux.
      splitBlocksLeaf(),
      // Write `blockCount` to aux for the iterate node to read.
      computeBlockCountLeaf(),
      // Per-block AES round body. Runtime sets state = input-blocks[i]
      // at iteration start and appends final state to output-blocks.
      iterateNode,
      // Mirror boundary: aux output-blocks → BytesState. This is the
      // final spec output (pre-unpad if the padding overlay is active).
      concatBlocksLeaf(),
    ],
  };
}
