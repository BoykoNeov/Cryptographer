/**
 * CTR (Counter) — the mode of operation, written once for every block cipher.
 *
 * CTR is the mode that stops using the block cipher as a block cipher. Rather
 * than encrypting the message, it encrypts a **counter** to manufacture a
 * keystream, then XORs that keystream with the message:
 *
 *   C_i = P_i ⊕ E_K(T_i)      T_0 = the nonce/IV, T_{i+1} = T_i + 1
 *
 * Three consequences fall out, and each one is a pedagogical payload:
 *
 *  1. **The forward cipher runs in both directions.** Decryption is
 *     `P_i = C_i ⊕ E_K(T_i)` — the *same* expression, because XOR is its own
 *     inverse. The inverse cipher is never invoked. This is why
 *     `BlockCipherCore` exposes `buildEncryptBody` / `buildDecryptBody`
 *     independently instead of assuming "decrypt ⇒ inverse body"; CTR is the
 *     mode that would have broken that assumption.
 *  2. **The blocks are independent.** Unlike CBC, block `i`'s keystream
 *     depends only on the counter, so nothing serializes.
 *  3. **No padding is needed**, because the message is XORed, not blocked —
 *     a 5-byte message wants only 5 keystream bytes. *(v1 caveat below.)*
 *
 * **Cipher-agnostic.** Like `modes/ecb.ts` and `modes/cbc.ts`, this builder
 * takes a `BlockCipherCore` and knows nothing else. It is also the mode that
 * most thoroughly exercises the core contract, because it is the first to seed
 * a core's body from the iterate's `chain` port rather than from `in` — the
 * body encrypts the COUNTER, and the message block never enters the cipher at
 * all. A core whose body only happened to work when fed the input block shows
 * up here.
 *
 * The shape it builds:
 *
 *   [
 *     <core key schedule>  (aux-only — publishes round keys once, before the loop)
 *     fetch-iv             (aux-load-bytes@1 — reads aux["iv"] = the initial counter T_0)
 *     iterate "ctr-blocks" {
 *       seedInput:     $input                       // the message bytes
 *       blockByteLength: core.blockByteLength
 *       chainInput:    port(fetch-iv,"output")      // T_0 bootstraps the counter
 *       chainFeedback: port(ctr-increment,"output") // T_{i+1} = T_i + 1
 *       bodyOutput:    port(ctr-xor,"output")       // P_i ⊕ keystream
 *       outputPorts:   ["out"]
 *       children: [
 *         <core FORWARD body, seeded from port(it,"chain")>  → keystream E(T_i)
 *         ctr-xor       (xor@1: port(it,"in") ⊕ keystream)
 *         ctr-increment (increment-counter@1 on port(it,"chain"))
 *       ]
 *     }
 *   ]
 *
 * ## The chain carries the counter
 *
 * CBC's `chain` port carries the previous ciphertext block; CTR reuses the
 * exact same runtime carry to hold `T_i` instead. Nothing in the runtime
 * changed to support this — the carry is a general "value threaded across
 * iterations", and what a mode threads through it is the mode's business. The
 * counter advances via a visible `increment-counter@1` leaf inside the body,
 * so the `+1` is a trace frame the learner can scrub to, not hidden runtime
 * behaviour.
 *
 * Note `ctr-increment` reads `port(it,"chain")` — the counter as it entered
 * this iteration — NOT the cipher body's output. It sits at the body's tail
 * for readability, but it is not downstream of the cipher: keystream
 * generation and counter advance are independent branches off the same value.
 *
 * ## Encrypt and decrypt are the same spec
 *
 * `direction` changes only the spec's `id`, `name`, and narration prose. Both
 * call `core.buildEncryptBody`. That is not a shortcut — it is the definition
 * of the mode, and running CTR-decrypt over CTR-encrypt's output in the
 * explorer is meant to make that land.
 *
 * ## v1 caveat: whole blocks only
 *
 * Real CTR truncates the final keystream block to the message's trailing
 * partial block and emits ciphertext exactly as long as the plaintext. This
 * build requires the message to reach a block boundary, so the padding overlay
 * stays engaged (`requiresPadding: true` in the mode table) — the runtime's
 * port-mode iterate rejects a non-multiple `seedInput`, and `xor@1` requires
 * equal-length operands, so honest partial-block support needs both a runtime
 * relaxation and a truncation step. Deferred deliberately: the cipher-agnostic
 * spine and the counter arithmetic are what CTR contributes to the mode
 * machine, and neither depends on the ragged tail.
 *
 * References: NIST SP 800-38A §6.5 + Appendix B.1 (CTR mode definition and the
 * standard incrementing function).
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../../core/types";
import type { BlockCipherCore, CipherDirection } from "../block-cipher-core";
import { port } from "../block-cipher-core";

// Aux key the App seeds the IV under. In CTR the IV *is* the initial counter
// block T_0 (SP 800-38A calls it the initial counter block); we reuse aux["iv"]
// and the existing IV input field rather than inventing a parallel "nonce"
// channel the UI would have to grow a second editor for.
const AUX_IV = "iv";

// The iterate node's id — the per-block dispatch boundary. The runtime injects
// each message block as `port(CTR_ITERATE_ID,"in")` and the running counter as
// `port(CTR_ITERATE_ID,"chain")`.
const CTR_ITERATE_ID = "ctr-blocks";

// The keystream-XOR leaf id, and the counter-advance leaf id. Held in one
// place because the KATs pin `ctr-xor:b{i}` / `ctr-increment:b{i}`.
const CTR_XOR_ID = "ctr-xor";
const CTR_INCREMENT_ID = "ctr-increment";

/**
 * Initial-counter narration. Block size is interpolated from the core because
 * the counter block is exactly one cipher block wide.
 */
const narrFetchIv = (core: BlockCipherCore): StepDocumentation => ({
  name: "Load initial counter",
  summary: `Read the ${core.blockByteLength}-byte initial counter block T₀ from aux (NIST SP 800-38A §6.5).`,
  detail: `## Load initial counter (T₀)

Reads the initial counter block from \`aux["iv"]\` and publishes it on a port so
the first iteration can encrypt it. In CTR the IV field holds what SP 800-38A
calls the **initial counter block**: the value that gets encrypted to make
block 0's keystream, and that every later block counts up from.

Unlike CBC's IV, this value never gets XORed with anything — it goes straight
into the cipher. Editing it shifts the whole keystream, so every output block
changes.

**It must never repeat under the same key.** Two messages encrypted from the
same starting counter produce the *same* keystream; XORing the two ciphertexts
then cancels the keystream out entirely and leaves the two plaintexts XORed
together. This is CTR's one unforgiving requirement.`,
  references: ["NIST SP 800-38A §6.5 (CTR)", "NIST SP 800-38A Appendix B (counter generation)"],
});

/**
 * Keystream-XOR narration. Direction-aware prose over an identical operation —
 * the point being that it IS identical.
 */
const narrCtrXor = (core: BlockCipherCore, isDecrypt: boolean): StepDocumentation => ({
  name: "Keystream XOR (CTR)",
  summary: isDecrypt
    ? "XOR the ciphertext block with the keystream to recover plaintext — the same operation that encrypted it."
    : "XOR the plaintext block with the encrypted counter to produce ciphertext.",
  detail: `## Keystream XOR (${isDecrypt ? "decrypt" : "encrypt"})

The counter block \`T_i\` has just been run through ${core.familyName} to produce one block of
**keystream**. This step XORs that keystream with the message block:

\`\`\`
${isDecrypt ? "P_i = C_i ⊕ " : "C_i = P_i ⊕ "}${core.familyName}_encrypt(T_i)
\`\`\`

${
  isDecrypt
    ? `Compare that with the encrypt side: \`C_i = P_i ⊕ ${core.familyName}_encrypt(T_i)\`. It is the
**same formula**. Decryption XORs the identical keystream back out, because a
value XORed with the same thing twice returns to itself. That is why CTR never
runs the inverse cipher — the ${core.familyName} box above is running *forwards* even though
this spec decrypts.`
    : `Note what did **not** enter the cipher: the plaintext. ${core.familyName} only ever sees the
counter. The message is combined with the result afterwards, which is what makes
CTR a stream cipher built out of a block cipher — and why decryption runs this
exact same forward path rather than an inverse.`
}`,
  references: ["NIST SP 800-38A §6.5 (CTR-Encrypt / CTR-Decrypt)"],
});

/** Counter-advance narration. */
const narrIncrement: StepDocumentation = {
  name: "Advance counter (CTR)",
  summary: "Add one to the counter block so the next block gets a different keystream.",
  detail: `## Advance counter

\`\`\`
T_{i+1} = T_i + 1
\`\`\`

Adds one to the counter block that entered this iteration, treating the whole
block as a big-endian number. The result rides the loop's carry into the next
iteration, where it becomes the value the cipher encrypts.

This is the step that makes every block's keystream different. Without it,
every block would be XORed with the same keystream — and XORing two such
ciphertext blocks together would cancel the keystream and leave the two
plaintext blocks XORed with each other.

Note that this reads the counter **as it arrived**, not the cipher's output.
Generating the keystream and advancing the counter are two independent branches
off the same value, which is exactly why CTR blocks don't depend on each other
and could be computed in any order.`,
  references: ["NIST SP 800-38A Appendix B.1 (standard incrementing function)"],
};

/** aux["iv"] (one block wide) → port output. The initial counter block T₀. */
const fetchIvLeaf = (core: BlockCipherCore): StepNode => ({
  kind: "step",
  id: "fetch-iv",
  type: "aux-load-bytes@1",
  params: { auxName: AUX_IV, byteLength: core.blockByteLength },
  narrationOverride: narrFetchIv(core),
});

/**
 * Build the CTR spec for any block cipher.
 *
 * @param core      the block cipher whose FORWARD body generates the keystream
 * @param direction affects the spec id, name, and prose only — both directions
 *                  build structurally identical specs (see the file header)
 */
export function buildCtrSpec(core: BlockCipherCore, direction: CipherDirection): CipherSpec {
  const isDecrypt = direction === "decrypt";

  const blockIn = port(CTR_ITERATE_ID, "in"); // the per-block message bytes
  const counterIn = port(CTR_ITERATE_ID, "chain"); // T_i, carried across iterations

  // The FORWARD cipher, seeded from the COUNTER — not from the message block.
  // This is the line that makes CTR the strictest test of a core's
  // seed-threading: `in` is never wired into the cipher at all.
  const keystream = core.buildEncryptBody(counterIn);

  // Message block ⊕ keystream. Identical for both directions.
  const ctrXor: StepNode = {
    kind: "step",
    id: CTR_XOR_ID,
    type: "xor@1",
    params: { inputCount: 2 },
    portInputs: { operand0: blockIn, operand1: keystream.output },
    narrationOverride: narrCtrXor(core, isDecrypt),
  };

  // T_{i+1} = T_i + 1. Reads the INCOMING counter (see the file header) —
  // parallel to the cipher, not downstream of it.
  const ctrIncrement: StepNode = {
    kind: "step",
    id: CTR_INCREMENT_ID,
    type: "increment-counter@1",
    params: {},
    portInputs: { counter: counterIn },
    narrationOverride: narrIncrement,
  };

  const specId = `${core.id}-ctr${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${core.displayName} CTR${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: CTR_ITERATE_ID,
    label: `CTR blocks (${core.familyName} keystream ⊕ message)`,
    seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    blockByteLength: core.blockByteLength,
    // The carry holds the counter: bootstrapped from T₀, advanced by +1.
    chainInput: port("fetch-iv", "output"),
    chainFeedback: port(CTR_INCREMENT_ID, "output"),
    bodyOutput: port(CTR_XOR_ID, "output"),
    outputPorts: ["out"],
    children: [...keystream.nodes, ctrXor, ctrIncrement],
  };

  return {
    id: specId,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      // As in CBC, the App seeds `aux["iv"]` alongside `aux["key"]`; here the
      // IV field's bytes are the initial counter block.
      key: { byteLength: core.keyByteLength },
    },
    steps: [
      // Key expansion runs once, outside the loop — its round keys reach every
      // iteration through the global aux map.
      core.buildKeySchedule(),
      // T₀ → a port the iterate's `chainInput` reads.
      fetchIvLeaf(core),
      iterateNode,
    ],
    outputFrom: port(CTR_ITERATE_ID, "out"),
  };
}
