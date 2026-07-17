/**
 * CBC (Cipher Block Chaining) — the mode of operation, written once for every
 * block cipher.
 *
 * CBC XORs each plaintext block with the previous ciphertext block before
 * encrypting it, turning the cipher into a true stream of dependencies and
 * removing ECB's "identical plaintext blocks → identical ciphertext blocks"
 * leak. The IV bootstraps the chain (block 0's "previous ciphertext" is the
 * IV).
 *
 * **Cipher-agnostic.** Like `modes/ecb.ts`, this builder takes a
 * `BlockCipherCore` and knows nothing else. The chaining rule below is
 * identical whether the cipher underneath is AES, Blowfish, or DES — which is
 * precisely why it is written once here rather than once per cipher.
 *
 * The shape it builds:
 *
 *   [
 *     <core key schedule>  (aux-only — publishes round keys once, before the loop)
 *     fetch-iv             (aux-load-bytes@1 — reads aux["iv"] onto a port)
 *     iterate "cbc-blocks" {
 *       seedInput:     $input                    // the (padded) plaintext bytes
 *       blockByteLength: core.blockByteLength     // the core's block width
 *       chainInput:    port(fetch-iv,"output")    // IV bootstraps the chain
 *       chainFeedback: <see below>                // advances the chain per block
 *       bodyOutput:    <see below>                // each block's result
 *       outputPorts:   ["out"]                    // concatenated output
 *       children:      [ CBC body ]
 *     }
 *   ]
 *   spec.outputFrom = port("cbc-blocks", "out")
 *
 * The runtime injects each input block as `port("cbc-blocks","in")` AND the
 * running chain value as `port("cbc-blocks","chain")` (the IV for block 0, then
 * `chainFeedback` of the previous iteration).
 *
 * ## The asymmetry (the load-bearing detail)
 *
 * Encrypt and decrypt are NOT mirror images — they differ in both the order of
 * operations and in *what feeds the chain*. Both ride the same uniform runtime
 * carry; the difference lives entirely in the spec:
 *
 * **Encrypt** (`C_i = E(P_i ⊕ C_{i-1})`, `C_{-1} = IV`):
 *   cbc-xor  (xor@1: port(it,"in") ⊕ port(it,"chain"))  → P_i ⊕ C_{i-1}
 *   cipher body, reading the cbc-xor output             → C_i
 *   bodyOutput = chainFeedback = body output (= C_i)     // OUTPUT feeds chain
 *
 * **Decrypt** (`P_i = D(C_i) ⊕ C_{i-1}`, `C_{-1} = IV`):
 *   inverse body, reading port(it,"in") (the raw C_i)   → D(C_i)
 *   cbc-xor  (xor@1: D(C_i) ⊕ port(it,"chain"))         → P_i
 *   bodyOutput = cbc-xor.output (= P_i)
 *   chainFeedback = port(it,"in") (= raw C_i)            // INPUT feeds chain
 *
 * Decrypt chains on its raw *input* because the chain value CBC needs is the
 * ciphertext, and on decrypt the ciphertext is what arrives, not what leaves.
 * That `chainFeedback = port(it,"in")` resolves because the runtime seeds the
 * body scope's node-output map with the injected `in`/`chain` ports and they
 * survive the body walk (see `runtime.ts` `walk`).
 *
 * Padding is layered on top by `applyPaddingScheme` exactly as for ECB:
 * encrypt prepends a pad and repoints the iterate's `seedInput` to it; decrypt
 * appends an unpad and moves `spec.outputFrom` onto it. `fetch-iv` reads
 * `aux["iv"]`, never `$input`, so the pad-input repoint leaves it untouched.
 *
 * References: NIST SP 800-38A §6.2 (CBC mode definition).
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../../core/types";
import type { BlockCipherCore, CipherDirection } from "../block-cipher-core";
import { port } from "../block-cipher-core";

// Aux key the App seeds the IV under (alongside aux["key"]). `fetch-iv` reads
// it; nothing writes it during the run.
const AUX_IV = "iv";

// The iterate node's id — the per-block dispatch boundary. The runtime injects
// each block as `port(CBC_ITERATE_ID,"in")` and the running chain value as
// `port(CBC_ITERATE_ID,"chain")`; the body's leaves read those ports.
const CBC_ITERATE_ID = "cbc-blocks";

// The chaining-XOR leaf id. Held in one place because both encrypt (body head)
// and decrypt (body tail) use it, and the KATs pin `cbc-xor:b{i}`.
const CBC_XOR_ID = "cbc-xor";

/**
 * IV narration. Block size is interpolated from the core because the IV is
 * exactly one block wide — 16 bytes for AES, 8 for Blowfish/DES.
 */
const narrFetchIv = (core: BlockCipherCore): StepDocumentation => ({
  name: "Load IV",
  summary: `Read the ${core.blockByteLength}-byte initialization vector from aux onto a port (NIST SP 800-38A §6.2).`,
  detail: `## Load IV

Reads the initialization vector from \`aux["iv"]\` and publishes it on a port so
the first block's chaining XOR can fold it in. The IV is the chain's bootstrap:
block 0 has no "previous ciphertext", so CBC uses the IV in its place.

The IV must be unpredictable (random) per message for CBC to be secure, but it
is **not** secret — it travels with the ciphertext. Editing it here changes
every ciphertext block (the chain diverges from block 0 onward).`,
  references: ["NIST SP 800-38A §6.2 (CBC)", "NIST SP 800-38A Appendix C (IV generation)"],
});

/**
 * Encrypt-side chain XOR narration. Uses the core's *family* name, not its
 * display name: "C_i = AES_encrypt(…)" is the textbook form, where
 * "AES-128_encrypt" would be needlessly specific about a variant the mode
 * doesn't care about.
 */
const narrCbcXorEncrypt = (core: BlockCipherCore): StepDocumentation => ({
  name: "Chain XOR (CBC)",
  summary: "XOR this plaintext block with the previous ciphertext block before encryption.",
  detail: `## Chain XOR (encrypt)

Before ${core.familyName} runs, the current plaintext block \`P_i\` is XORed with the previous
ciphertext block \`C_{i-1}\` (or the IV for block 0):

\`\`\`
C_i = ${core.familyName}_encrypt(P_i ⊕ C_{i-1})
\`\`\`

This is what makes CBC chain: each block's encryption depends on every block
before it, so two identical plaintext blocks encrypt to different ciphertext —
the structural fix for the ECB "Tux leak". The chained value carries to the
next iteration on the iterate's \`chain\` port (the ${core.familyName} output \`C_i\`).`,
  references: ["NIST SP 800-38A §6.2 (CBC-Encrypt)"],
});

/** Decrypt-side chain XOR narration. See `narrCbcXorEncrypt` on family naming. */
const narrCbcXorDecrypt = (core: BlockCipherCore): StepDocumentation => ({
  name: "Chain XOR (CBC)",
  summary: "XOR the decrypted block with the previous ciphertext block to recover plaintext.",
  detail: `## Chain XOR (decrypt)

CBC decryption inverts the chain in the opposite order: first run the ${core.familyName}
inverse cipher on the raw ciphertext block \`C_i\`, *then* XOR with the previous
ciphertext block \`C_{i-1}\` (or the IV for block 0):

\`\`\`
P_i = ${core.familyName}_decrypt(C_i) ⊕ C_{i-1}
\`\`\`

Note the asymmetry vs encrypt: here the chain value that carries to the next
iteration is the *raw input* block \`C_i\` (not the decrypted output) — the
iterate's \`chainFeedback\` reads \`port("cbc-blocks","in")\`.`,
  references: ["NIST SP 800-38A §6.2 (CBC-Decrypt)"],
});

/** aux["iv"] (one block wide) → port output. */
const fetchIvLeaf = (core: BlockCipherCore): StepNode => ({
  kind: "step",
  id: "fetch-iv",
  type: "aux-load-bytes@1",
  params: { auxName: AUX_IV, byteLength: core.blockByteLength },
  narrationOverride: narrFetchIv(core),
});

/**
 * Build the CBC spec for any block cipher.
 *
 * @param core      the block cipher to chain per block
 * @param direction encrypt runs the forward body, decrypt the inverse — and
 *                  the two differ in chain feedback, see the file header
 */
export function buildCbcSpec(core: BlockCipherCore, direction: CipherDirection): CipherSpec {
  const isDecrypt = direction === "decrypt";

  const blockIn = port(CBC_ITERATE_ID, "in"); // the per-block input bytes
  const chainIn = port(CBC_ITERATE_ID, "chain"); // the previous-ciphertext / IV

  // Build the per-block body + the iterate's bodyOutput/chainFeedback wiring.
  let children: StepNode[];
  let bodyOutput: PortBinding;
  let chainFeedback: PortBinding;

  if (isDecrypt) {
    // Inverse cipher on the raw ciphertext block, then XOR with the chain.
    const body = core.buildDecryptBody(blockIn);
    const cbcXor: StepNode = {
      kind: "step",
      id: CBC_XOR_ID,
      type: "xor@1",
      params: { inputCount: 2 },
      // operand0 = the inverse cipher's published exit; operand1 = the chain.
      portInputs: { operand0: body.output, operand1: chainIn },
      narrationOverride: narrCbcXorDecrypt(core),
    };
    children = [...body.nodes, cbcXor];
    bodyOutput = port(CBC_XOR_ID, "output"); // P_i
    chainFeedback = blockIn; // next chain = the raw ciphertext block C_i
  } else {
    // XOR the plaintext block with the chain, then encrypt → ciphertext.
    const cbcXor: StepNode = {
      kind: "step",
      id: CBC_XOR_ID,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: blockIn, operand1: chainIn },
      narrationOverride: narrCbcXorEncrypt(core),
    };
    const body = core.buildEncryptBody(port(CBC_XOR_ID, "output"));
    children = [cbcXor, ...body.nodes];
    bodyOutput = body.output; // C_i
    chainFeedback = body.output; // next chain = the output C_i
  }

  const specId = `${core.id}-cbc${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${core.displayName} CBC${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: CBC_ITERATE_ID,
    label: `CBC blocks (per-block chained ${core.familyName})`,
    // Port mode: split the (padded) input from `$input` into block-sized
    // chunks; the chain carries the previous-ciphertext value across blocks.
    seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    blockByteLength: core.blockByteLength,
    chainInput: port("fetch-iv", "output"),
    chainFeedback,
    bodyOutput,
    outputPorts: ["out"],
    children,
  };

  return {
    id: specId,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      // Both encrypt and decrypt expect `aux["iv"]` to be seeded by the App
      // alongside `aux["key"]`. The IV input field in the UI is the
      // user-facing source; localStorage persists it across reloads.
      key: { byteLength: core.keyByteLength },
    },
    steps: [
      // Key expansion runs once, outside the loop — it publishes round keys to
      // aux, which every iteration reads.
      core.buildKeySchedule(),
      // Pre-loop chain bootstrap: aux["iv"] → a port the iterate's
      // `chainInput` reads. The first iteration's chain XOR uses it.
      fetchIvLeaf(core),
      // Per-block CBC body (see file header for the encrypt/decrypt asymmetry).
      iterateNode,
    ],
    // The cipher's output is the iterate's concatenated per-block exit.
    outputFrom: port(CBC_ITERATE_ID, "out"),
  };
}
