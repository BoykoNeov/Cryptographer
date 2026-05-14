/**
 * Shared factory for the AES-CBC (Cipher Block Chaining) multi-block specs.
 *
 * CBC is the chaining mode where each plaintext block is XORed with the
 * previous ciphertext block before encryption — turning the cipher into
 * a true stream of dependencies and removing the "identical plaintext
 * blocks → identical ciphertext blocks" ECB leak. The IV bootstraps the
 * chain (block 0's "previous ciphertext" is the IV).
 *
 * Spec shape (encrypt):
 *
 *   [
 *     key-expansion              (writes roundKey.0..N to aux; passthrough)
 *     split-blocks               (writes aux[input-blocks]: MatrixState[])
 *     compute-block-count        (writes aux[blockCount])
 *     iv-load                    (aux[iv] (bytes) → aux[chain] (MatrixState))
 *     iterate count=blockCount,
 *             blocks=input-blocks,
 *             out=output-blocks {
 *       xor-aux-into-state(chain)        ← state ⊕= prev-ciphertext (or IV)
 *       initial AddRoundKey               ┐
 *       round.1..N-1                       │ AES core (same body as ECB)
 *       round.N (no MixColumns)           ┘
 *       state-to-aux(chain)              ← snapshot ciphertext for next iter
 *     }
 *     concat-blocks              (aux[output-blocks] → BytesState)
 *   ]
 *
 * Decrypt (same shell, inverted body):
 *
 *   [
 *     key-expansion, split-blocks, compute-block-count, iv-load,
 *     iterate { … inverse body … },
 *     concat-blocks
 *   ]
 *
 * Inverse body:
 *
 *   state-to-aux(next-chain)     ← snapshot incoming ciphertext C_i
 *   inv-initial AddRoundKey
 *   inv-round.{N-1}..1
 *   inv-round.0 (no InvMixColumns)
 *   xor-aux-into-state(chain)    ← state ⊕= prev ciphertext (or IV)
 *   aux-copy(next-chain → chain) ← advance chain := C_i for next iter
 *
 * Cycle proof (iter i): chain holds C_{i-1} (or IV for i=0). After
 * state-to-aux(next-chain), aux[next-chain]=C_i and the running state is
 * still C_i. Inverse AES gives state=P_i ⊕ C_{i-1}. XOR with chain
 * (=C_{i-1}) yields P_i — that's the plaintext block. aux-copy then
 * advances chain := next-chain = C_i so the next iteration's XOR uses
 * the correct previous ciphertext. The padding/concat shell collects each
 * P_i into the final BytesState.
 *
 * Reuses `aes-ecb-builder.ts`'s key-expansion + split/concat/count leaves
 * and the round-body helper in `aes-round-builder.ts`. The only NEW spec
 * code here is the chaining-XOR pre/post-round leaves and the iv-load
 * pre-loop step.
 *
 * References: NIST SP 800-38A §6.2 (CBC mode definition).
 */

import type { CipherSpec, StepNode } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import type { AesVariant, CipherDirection } from "./aes-ecb-builder";
import { buildAesDecryptBody, buildAesEncryptBody } from "./aes-round-builder";

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

// Aux key names. Held in one place so the chain plumbing reads
// consistently across encrypt + decrypt and matches the App-level seed
// (`aux["iv"]`).
const AUX_INPUT_BLOCKS = "input-blocks";
const AUX_OUTPUT_BLOCKS = "output-blocks";
const AUX_BLOCK_COUNT = "blockCount";
const AUX_IV = "iv";
const AUX_CHAIN = "chain";
const AUX_NEXT_CHAIN = "next-chain"; // decrypt-only — the in-loop snapshot.

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

const ivLoadLeaf = (): StepNode => ({
  kind: "step",
  id: "iv-load",
  type: "generic.iv-load@1",
  params: { ivAuxName: AUX_IV, outAuxName: AUX_CHAIN },
});

// In-loop encrypt leaves. Named with the "cbc-" prefix so they don't
// collide with anything in the AES round body (round.N.*).
const cbcXorEncryptLeaf = (): StepNode => ({
  kind: "step",
  id: "cbc-xor",
  type: "generic.xor-aux-into-state@1",
  params: { auxName: AUX_CHAIN },
});

const cbcSnapshotEncryptLeaf = (): StepNode => ({
  kind: "step",
  id: "cbc-snapshot",
  type: "generic.state-to-aux@1",
  params: { auxName: AUX_CHAIN },
});

// In-loop decrypt leaves.
const cbcSnapshotInputLeaf = (): StepNode => ({
  kind: "step",
  id: "cbc-snapshot-input",
  type: "generic.state-to-aux@1",
  params: { auxName: AUX_NEXT_CHAIN },
});

const cbcXorDecryptLeaf = (): StepNode => ({
  kind: "step",
  id: "cbc-xor",
  type: "generic.xor-aux-into-state@1",
  params: { auxName: AUX_CHAIN },
});

const cbcAdvanceChainLeaf = (): StepNode => ({
  kind: "step",
  id: "cbc-advance-chain",
  type: "generic.aux-copy@1",
  params: { from: AUX_NEXT_CHAIN, to: AUX_CHAIN },
});

export function buildAesCbcSpec(variant: AesVariant, direction: CipherDirection): CipherSpec {
  const rounds = ROUNDS_BY_VARIANT[variant];
  const keyBytes = KEY_BYTES_BY_VARIANT[variant];
  const isDecrypt = direction === "decrypt";
  const aesBody = isDecrypt ? buildAesDecryptBody(rounds) : buildAesEncryptBody(rounds);

  // Encrypt: XOR first (mix in previous ciphertext) → AES → snapshot.
  // Decrypt: snapshot first (save current ciphertext) → AES⁻¹ → XOR →
  //          advance chain := saved snapshot.
  const iterateChildren: StepNode[] = isDecrypt
    ? [cbcSnapshotInputLeaf(), ...aesBody, cbcXorDecryptLeaf(), cbcAdvanceChainLeaf()]
    : [cbcXorEncryptLeaf(), ...aesBody, cbcSnapshotEncryptLeaf()];

  const specId = `${variant}-cbc${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${VARIANT_DISPLAY[variant]} CBC${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: "cbc-blocks",
    label: "CBC blocks (per-block chained AES)",
    countFromAux: AUX_BLOCK_COUNT,
    blocksFromAux: AUX_INPUT_BLOCKS,
    outBlocksAux: AUX_OUTPUT_BLOCKS,
    children: iterateChildren,
  };

  return {
    id: specId,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      // Both encrypt and decrypt expect `aux["iv"]` to be seeded by the
      // App alongside `aux["key"]`. The IV input field in the UI is the
      // user-facing source; localStorage persists it across reloads.
      key: { byteLength: keyBytes },
    },
    steps: [
      // Key expansion runs once, outside the loop. State passes through.
      keyExpansionLeaf(rounds),
      // BytesState → MatrixState[] boundary; passthrough state.
      splitBlocksLeaf(),
      computeBlockCountLeaf(),
      // Pre-loop chain bootstrap: aux["iv"] (Uint8Array, 16) → aux[
      // "chain"] (MatrixState). The first iteration's XOR reads this.
      ivLoadLeaf(),
      // Per-block CBC body. Encrypt: XOR → AES → snapshot. Decrypt:
      // snapshot → AES⁻¹ → XOR → advance.
      iterateNode,
      // Mirror of ECB's post-loop: aux[output-blocks] → BytesState.
      concatBlocksLeaf(),
    ],
  };
}
