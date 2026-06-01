/**
 * Shared factory for the AES-CBC (Cipher Block Chaining) multi-block specs.
 *
 * CBC is the chaining mode where each plaintext block is XORed with the
 * previous ciphertext block before encryption — turning the cipher into
 * a true stream of dependencies and removing the "identical plaintext
 * blocks → identical ciphertext blocks" ECB leak. The IV bootstraps the
 * chain (block 0's "previous ciphertext" is the IV).
 *
 * **Byte-native (scaffolding-suppression Slice B1.4b).** Like ECB, CBC is now
 * a pure port-graph spec — every leaf consumes/emits only `Uint8Array`. The
 * matrix `split-blocks`/`iv-load`/`concat-blocks` boundary, the matrix round
 * body, and the aux-mediated chain (`state-to-aux`/`xor-aux-into-state`/
 * `aux-copy`) are all gone. The cross-iteration chain rides a **port** instead
 * of an aux slot, via the port-mode `iterate`'s `chainInput`/`chainFeedback`
 * fields (B1.4b runtime):
 *
 *   [
 *     key-expansion (aux-only — writes roundKey.0..N once, before the loop)
 *     fetch-iv      (aux-load-bytes@1 — reads aux["iv"] (16 bytes) onto a port)
 *     iterate "cbc-blocks" {
 *       seedInput:     $input                  // the (padded) plaintext bytes
 *       blockByteLength: 16                     // split into 16-byte AES blocks
 *       chainInput:    port(fetch-iv,"output")  // IV bootstraps the chain
 *       chainFeedback: <see below>              // advances the chain per block
 *       bodyOutput:    <see below>              // each block's result
 *       outputPorts:   ["out"]                  // concatenated output
 *       children:      [ byte-native CBC body ]
 *     }
 *   ]
 *   spec.outputFrom = port("cbc-blocks", "out")
 *
 * The runtime injects each 16-byte input block as `port("cbc-blocks","in")`
 * AND the running chain value as `port("cbc-blocks","chain")` (the IV for
 * block 0, then `chainFeedback` of the previous iteration). The encrypt /
 * decrypt asymmetry lives entirely in the spec — same uniform runtime carry:
 *
 * **Encrypt body** (`C_i = E(P_i ⊕ C_{i-1})`, `C_{-1} = IV`):
 *   cbc-xor  (xor@1: port(it,"in") ⊕ port(it,"chain"))  → P_i ⊕ C_{i-1}
 *   AES encrypt body, reading the cbc-xor output           → C_i
 *   bodyOutput = chainFeedback = round.N.out (= C_i)        // output feeds chain
 *
 * **Decrypt body** (`P_i = D(C_i) ⊕ C_{i-1}`, `C_{-1} = IV`):
 *   AES decrypt body, reading port(it,"in") (the raw C_i)  → D(C_i)
 *   cbc-xor  (xor@1: D(C_i) ⊕ port(it,"chain"))            → P_i
 *   bodyOutput = cbc-xor.output (= P_i)
 *   chainFeedback = port(it,"in") (= raw C_i)               // input feeds chain
 *
 * That `chainFeedback = port(it,"in")` resolves because the runtime seeds the
 * body scope's node-output map with the injected `in`/`chain` ports and they
 * survive the body walk (see `runtime.ts` `walk`).
 *
 * Padding is layered on top by `applyPaddingScheme` exactly as for byte-native
 * ECB (the `hasByteNativeIterate` branch): encrypt prepends `pkcs7-pad` and
 * repoints the iterate's `seedInput` to it; decrypt appends `pkcs7-unpad` and
 * moves `spec.outputFrom` onto it. `fetch-iv` reads `aux["iv"]`, never
 * `$input`, so the pad-input repoint leaves it untouched.
 *
 * Variant-aware (AES-128/192/256) — only the round count differs (10/12/14);
 * the byte-native body is variant-agnostic.
 *
 * References: NIST SP 800-38A §6.2 (CBC mode definition).
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import type { AesVariant, CipherDirection } from "./aes-ecb-builder";
import { buildAesKeyScheduleNative } from "./aes-key-schedule-builder-native";
import {
  aesNativeDecryptOutputFrom,
  aesNativeOutputFrom,
  buildAesDecryptBodyNative,
  buildAesEncryptBodyNative,
} from "./aes-round-builder-native";

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

// Aux key the App seeds the IV under (alongside aux["key"]). `fetch-iv` reads
// it; nothing writes it during the run.
const AUX_IV = "iv";

// The iterate node's id — the per-block dispatch boundary. The runtime injects
// each 16-byte block as `port(CBC_ITERATE_ID,"in")` and the running chain value
// as `port(CBC_ITERATE_ID,"chain")`; the body's leaves read those ports.
const CBC_ITERATE_ID = "cbc-blocks";

// The chaining-XOR leaf id. Held in one place because both encrypt (body head)
// and decrypt (body tail) use it, and the KAT pins `cbc-xor:b{i}`.
const CBC_XOR_ID = "cbc-xor";

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

const NARR_FETCH_IV: StepDocumentation = {
  name: "Load IV",
  summary: "Read the 16-byte initialization vector from aux onto a port (NIST SP 800-38A §6.2).",
  detail: `## Load IV

Reads the initialization vector from \`aux["iv"]\` and publishes it on a port so
the first block's chaining XOR can fold it in. The IV is the chain's bootstrap:
block 0 has no "previous ciphertext", so CBC uses the IV in its place.

The IV must be unpredictable (random) per message for CBC to be secure, but it
is **not** secret — it travels with the ciphertext. Editing it here changes
every ciphertext block (the chain diverges from block 0 onward).`,
  references: ["NIST SP 800-38A §6.2 (CBC)", "NIST SP 800-38A Appendix C (IV generation)"],
};

const NARR_CBC_XOR_ENCRYPT: StepDocumentation = {
  name: "Chain XOR (CBC)",
  summary: "XOR this plaintext block with the previous ciphertext block before encryption.",
  detail: `## Chain XOR (encrypt)

Before AES runs, the current plaintext block \`P_i\` is XORed with the previous
ciphertext block \`C_{i-1}\` (or the IV for block 0):

\`\`\`
C_i = AES_encrypt(P_i ⊕ C_{i-1})
\`\`\`

This is what makes CBC chain: each block's encryption depends on every block
before it, so two identical plaintext blocks encrypt to different ciphertext —
the structural fix for the ECB "Tux leak". The chained value carries to the
next iteration on the iterate's \`chain\` port (the AES output \`C_i\`).`,
  references: ["NIST SP 800-38A §6.2 (CBC-Encrypt)"],
};

const NARR_CBC_XOR_DECRYPT: StepDocumentation = {
  name: "Chain XOR (CBC)",
  summary: "XOR the decrypted block with the previous ciphertext block to recover plaintext.",
  detail: `## Chain XOR (decrypt)

CBC decryption inverts the chain in the opposite order: first run the AES
inverse cipher on the raw ciphertext block \`C_i\`, *then* XOR with the previous
ciphertext block \`C_{i-1}\` (or the IV for block 0):

\`\`\`
P_i = AES_decrypt(C_i) ⊕ C_{i-1}
\`\`\`

Note the asymmetry vs encrypt: here the chain value that carries to the next
iteration is the *raw input* block \`C_i\` (not the decrypted output) — the
iterate's \`chainFeedback\` reads \`port("cbc-blocks","in")\`.`,
  references: ["NIST SP 800-38A §6.2 (CBC-Decrypt)"],
};

/** aux["iv"] (16 bytes) → port output. The byte-native replacement for `generic.iv-load@1`. */
const fetchIvLeaf = (): StepNode => ({
  kind: "step",
  id: "fetch-iv",
  type: "aux-load-bytes@1",
  params: { auxName: AUX_IV, byteLength: BLOCK_SIZE },
  narrationOverride: NARR_FETCH_IV,
});

export function buildAesCbcSpec(variant: AesVariant, direction: CipherDirection): CipherSpec {
  const rounds = ROUNDS_BY_VARIANT[variant];
  const keyBytes = KEY_BYTES_BY_VARIANT[variant];
  const isDecrypt = direction === "decrypt";

  const blockIn = port(CBC_ITERATE_ID, "in"); // the per-block input bytes
  const chainIn = port(CBC_ITERATE_ID, "chain"); // the previous-ciphertext / IV

  // Build the per-block body + the iterate's bodyOutput/chainFeedback wiring.
  let children: StepNode[];
  let bodyOutput: PortBinding;
  let chainFeedback: PortBinding;

  if (isDecrypt) {
    // AES⁻¹ on the raw ciphertext block, then XOR with the chain → plaintext.
    const aesBody = buildAesDecryptBodyNative(rounds, blockIn);
    const cbcXor: StepNode = {
      kind: "step",
      id: CBC_XOR_ID,
      type: "xor@1",
      params: { inputCount: 2 },
      // operand0 = the AES inverse output (the GROUP's published "out" port —
      // use the helper, not the inner leaf's "output"); operand1 = the chain.
      portInputs: { operand0: aesNativeDecryptOutputFrom(), operand1: chainIn },
      narrationOverride: NARR_CBC_XOR_DECRYPT,
    };
    children = [...aesBody, cbcXor];
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
      narrationOverride: NARR_CBC_XOR_ENCRYPT,
    };
    const aesBody = buildAesEncryptBodyNative(rounds, port(CBC_XOR_ID, "output"));
    children = [cbcXor, ...aesBody];
    bodyOutput = aesNativeOutputFrom(rounds); // C_i
    chainFeedback = aesNativeOutputFrom(rounds); // next chain = the output C_i
  }

  const specId = `${variant}-cbc${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${VARIANT_DISPLAY[variant]} CBC${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: CBC_ITERATE_ID,
    label: "CBC blocks (per-block chained AES)",
    // Port mode (B1.4): split the (padded) input from `$input` into 16-byte
    // blocks; the chain carries the previous-ciphertext value across blocks.
    seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    blockByteLength: BLOCK_SIZE,
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
      key: { byteLength: keyBytes },
    },
    steps: [
      // Key expansion runs once, outside the loop. The decomposed schedule
      // publishes roundKey.0..N to aux (B-minimal — consumers untouched).
      buildAesKeyScheduleNative(rounds, keyBytes / 4),
      // Pre-loop chain bootstrap: aux["iv"] (Uint8Array, 16) → a port the
      // iterate's `chainInput` reads. The first iteration's chain XOR uses it.
      fetchIvLeaf(),
      // Per-block CBC body (see file header for the encrypt/decrypt asymmetry).
      iterateNode,
    ],
    // The cipher's output is the iterate's concatenated per-block exit.
    outputFrom: port(CBC_ITERATE_ID, "out"),
  };
}
