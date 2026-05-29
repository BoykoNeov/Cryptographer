/**
 * Shared factory for the AES-ECB (Electronic Codebook) multi-block specs.
 *
 * ECB is the simplest cipher mode — encrypt each block independently, no
 * chaining, no IV. Famous as the "what NOT to do" mode: identical
 * plaintext blocks produce identical ciphertext blocks, leaking structure
 * (the Tux-image leak). We ship it because that leak is the pedagogical
 * setup for understanding why CBC and CTR exist.
 *
 * **Byte-native (scaffolding-suppression Slice B1.4).** ECB is a pure
 * port-graph spec — every leaf consumes/emits only `Uint8Array`. The matrix
 * `split-blocks`/`compute-block-count`/`concat-blocks` boundary and the
 * matrix round body are gone; the per-block AES body is the same byte-native
 * builder the single-block specs use (`aes-round-builder-native.ts`), wrapped
 * in a port-mode `iterate`:
 *
 *   [
 *     key-expansion (aux-only — writes roundKey.0..N once, before the loop)
 *     iterate "ecb-blocks" {
 *       seedInput:  $input            // the (padded) plaintext byte array
 *       blockByteLength: 16           // split into 16-byte AES blocks
 *       bodyOutput: round.N.out       // each block's ciphertext
 *       outputPorts: ["out"]          // concatenated ciphertext
 *       children:   [ byte-native AES body, reading port("ecb-blocks","in") ]
 *     }
 *   ]
 *   spec.outputFrom = port("ecb-blocks", "out")
 *
 * The runtime resolves `seedInput` in the parent scope, slices it into
 * 16-byte chunks, injects each chunk as `port("ecb-blocks", "in")` into the
 * body scope (so the body's initial AddRoundKey reads the block), collects
 * each iteration's `bodyOutput` bytes, and publishes the concatenation on
 * `outputPorts`. No `state` thread, no aux block array.
 *
 * Padding is layered on top by `applyPaddingScheme`: the encrypt spec gets a
 * `pkcs7-pad` prepended whose output the iterate's `seedInput` is repointed
 * to; the decrypt spec gets a `pkcs7-unpad` appended and `spec.outputFrom`
 * moved onto it. The unpadded spec is a valid cipher only when the input
 * length is already a multiple of 16 — the iterate's split enforces that.
 *
 * Variant-aware (AES-128/192/256) — only the round count differs (10/12/14);
 * the byte-native body is variant-agnostic.
 */

import type { CipherSpec, PortBinding, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import {
  aesNativeDecryptOutputFrom,
  aesNativeOutputFrom,
  buildAesDecryptBodyNative,
  buildAesEncryptBodyNative,
} from "./aes-round-builder-native";

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

const BLOCK_SIZE = 16;

// The iterate node's id is the per-block dispatch boundary. The runtime
// injects each 16-byte block as `port(ECB_ITERATE_ID, "in")`; the body's
// head reads that port.
const ECB_ITERATE_ID = "ecb-blocks";

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

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

export function buildAesEcbSpec(variant: AesVariant, direction: CipherDirection): CipherSpec {
  const rounds = ROUNDS_BY_VARIANT[variant];
  const keyBytes = KEY_BYTES_BY_VARIANT[variant];
  const isDecrypt = direction === "decrypt";

  // The per-block AES body reads its block bytes from `port(ECB_ITERATE_ID,
  // "in")` (injected by the iterate) instead of the single-block `$input`.
  const blockSource = port(ECB_ITERATE_ID, "in");
  const body = isDecrypt
    ? buildAesDecryptBodyNative(rounds, blockSource)
    : buildAesEncryptBodyNative(rounds, blockSource);
  // Each block's result is the body's published cipher exit (final round).
  const bodyOutput = isDecrypt ? aesNativeDecryptOutputFrom() : aesNativeOutputFrom(rounds);

  const specId = `${variant}-ecb${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${VARIANT_DISPLAY[variant]} ECB${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: ECB_ITERATE_ID,
    label: "ECB blocks (per-block AES)",
    // Port mode (B1.4): split the (padded) plaintext from `$input` into
    // 16-byte blocks, run the body per block, concatenate the results.
    seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    blockByteLength: BLOCK_SIZE,
    bodyOutput,
    outputPorts: ["out"],
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
      // Key expansion runs once total — outside the per-block loop. Writes
      // roundKey.0..N to aux; every block's AddRoundKey reads them.
      keyExpansionLeaf(rounds),
      iterateNode,
    ],
    // The cipher's output is the iterate's concatenated per-block exit.
    outputFrom: port(ECB_ITERATE_ID, "out"),
  };
}
