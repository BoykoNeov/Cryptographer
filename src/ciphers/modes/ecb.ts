/**
 * ECB (Electronic Codebook) — the mode of operation, written once for every
 * block cipher.
 *
 * ECB is the simplest way to stretch a block cipher over a long message:
 * encrypt each block independently, no chaining, no IV. It is famous as the
 * "what NOT to do" mode — identical plaintext blocks produce identical
 * ciphertext blocks, leaking the plaintext's structure (the Tux-image leak).
 * We ship it because that leak is the pedagogical setup for why CBC and CTR
 * exist.
 *
 * **Cipher-agnostic.** This builder knows nothing about AES, Blowfish, or any
 * other cipher — it takes a `BlockCipherCore` and asks it for a key schedule
 * and a body. Everything that used to be AES-specific (round count, block
 * size, body builders) now arrives through the core, so a new cipher gets ECB
 * for free the moment its core exists.
 *
 * The shape it builds:
 *
 *   [
 *     <core key schedule>   (aux-only — publishes round keys once, before the loop)
 *     iterate "ecb-blocks" {
 *       seedInput:  $input                    // the (padded) plaintext bytes
 *       blockByteLength: core.blockByteLength // split into the core's blocks
 *       bodyOutput: <core body's exit>        // each block's ciphertext
 *       outputPorts: ["out"]                  // concatenated ciphertext
 *       children:   [ core body, reading port("ecb-blocks","in") ]
 *     }
 *   ]
 *   spec.outputFrom = port("ecb-blocks", "out")
 *
 * The runtime resolves `seedInput` in the parent scope, slices it into
 * block-sized chunks, injects each chunk as `port("ecb-blocks","in")` into the
 * body scope (so the body's head reads the block), collects each iteration's
 * `bodyOutput` bytes, and publishes the concatenation on `outputPorts`.
 *
 * The key schedule sits *outside* the loop and runs once — it depends only on
 * `aux["key"]`, never on the plaintext. Its round keys reach every iteration
 * because aux is global and crosses the iterate's scope boundary freely.
 *
 * Padding is layered on top by `applyPaddingScheme`: the encrypt spec gets a
 * pad step prepended whose output the iterate's `seedInput` is repointed to;
 * the decrypt spec gets an unpad appended and `spec.outputFrom` moved onto it.
 * The unpadded spec is a valid cipher only when the input length is already a
 * multiple of the block size — the iterate's split enforces that.
 *
 * References: NIST SP 800-38A §6.1 (ECB mode definition).
 */

import type { CipherSpec, StepNode } from "../../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../../core/types";
import type { BlockCipherCore, CipherDirection } from "../block-cipher-core";
import { port } from "../block-cipher-core";

// The iterate node's id is the per-block dispatch boundary. The runtime
// injects each block as `port(ECB_ITERATE_ID,"in")`; the body's head reads
// that port. Cipher-independent, so the KAT's `:b{i}` stepId expectations
// hold for every core.
const ECB_ITERATE_ID = "ecb-blocks";

/**
 * Build the ECB spec for any block cipher.
 *
 * @param core      the block cipher to repeat per block
 * @param direction encrypt runs the forward body, decrypt the inverse
 */
export function buildEcbSpec(core: BlockCipherCore, direction: CipherDirection): CipherSpec {
  const isDecrypt = direction === "decrypt";

  // The per-block body reads its bytes from `port(ECB_ITERATE_ID,"in")`
  // (injected by the iterate) instead of the single-block `$input`.
  const blockSource = port(ECB_ITERATE_ID, "in");
  const body = isDecrypt ? core.buildDecryptBody(blockSource) : core.buildEncryptBody(blockSource);

  const specId = `${core.id}-ecb${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${core.displayName} ECB${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: ECB_ITERATE_ID,
    label: `ECB blocks (per-block ${core.familyName})`,
    // Port mode: split the (padded) plaintext from `$input` into block-sized
    // chunks, run the body per block, concatenate the results.
    seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    blockByteLength: core.blockByteLength,
    bodyOutput: body.output,
    outputPorts: ["out"],
    children: [...body.nodes],
  };

  return {
    id: specId,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: core.keyByteLength },
    },
    steps: [
      // Key expansion runs once total — outside the per-block loop. It
      // publishes its round keys to aux; every block's body reads them.
      core.buildKeySchedule(),
      iterateNode,
    ],
    // The cipher's output is the iterate's concatenated per-block exit.
    outputFrom: port(ECB_ITERATE_ID, "out"),
  };
}
