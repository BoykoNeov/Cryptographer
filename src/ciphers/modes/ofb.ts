/**
 * OFB (Output Feedback) — the mode of operation, written once for every block
 * cipher.
 *
 * OFB is the fifth and last of the confidentiality modes NIST SP 800-38A
 * defines, and the one whose keystream owes nothing at all to the message:
 *
 *   O_0 = the IV,  O_j = E_K(O_{j-1}),  C_i = P_i ⊕ O_{i+1}
 *
 * The cipher is run on its **own previous output**, over and over, and that
 * chain of encryptions IS the keystream. Nothing the user typed ever enters it.
 *
 * ## Where it sits between CFB and CTR
 *
 * It shares CFB's *shape* — a one-block feedback register, bootstrapped from
 * the IV, encrypted each iteration — and CTR's *symmetry*. Line them up by
 * what refills the register:
 *
 *   CFB:  register ← the previous CIPHERTEXT block   (message-dependent)
 *   OFB:  register ← the previous KEYSTREAM block    (message-independent)
 *   CTR:  register ← counter + 1                     (message-independent)
 *
 * That one column is the whole mode, and it has three consequences worth
 * reading the trace for:
 *
 *  - **The keystream is precomputable.** It depends only on the key and the IV,
 *    so a receiver can generate it *before* the ciphertext arrives — something
 *    CFB, whose register needs the previous ciphertext block, cannot do.
 *  - **But it is not seekable.** To reach block 1000 you must actually perform
 *    1000 encryptions, because each one's input is the last one's output. CTR
 *    gets to block 1000 by adding 1000 to the counter and encrypting once. This
 *    is the single practical reason CTR displaced OFB.
 *  - **Errors do not propagate.** Flip a bit of ciphertext and exactly that bit
 *    of plaintext flips; the register never saw the ciphertext, so no later
 *    block is disturbed. CFB is the opposite (one corrupt byte damages its own
 *    block and all of the next), and that contrast is the clearest thing the
 *    two modes teach side by side.
 *
 * ## Encrypt and decrypt are the SAME spec
 *
 * This is where OFB departs from the mode it is templated on. CFB's two
 * directions differ in one wire, because its register must hold the ciphertext
 * and which port carries the ciphertext flips with direction. OFB's register
 * holds the keystream, which is produced identically no matter which way the
 * spec runs — so there is no `isDecrypt` branch here at all. The two specs
 * differ in their id and their prose and in nothing else, exactly as CTR's do.
 *
 * The shape it builds:
 *
 *   [
 *     <core key schedule>  (aux-only — publishes round keys once, before the loop)
 *     fetch-iv             (aux-load-bytes@1 — reads aux["iv"] = the initial register O_0)
 *     iterate "ofb-blocks" {
 *       seedInput:     $input                       // the message bytes
 *       blockByteLength: core.blockByteLength
 *       allowPartialFinalBlock: true                // the ragged tail (below)
 *       chainInput:    port(fetch-iv,"output")      // O_0 = IV bootstraps the register
 *       chainFeedback: <core body output>           // O_j — THE line that defines OFB
 *       bodyOutput:    port(ofb-xor,"output")
 *       outputPorts:   ["out"]
 *       children: [
 *         <core FORWARD body, seeded from port(it,"chain")>  → keystream O_j = E(O_{j-1})
 *         ofb-trim      (truncate-to-reference@1: keystream ↓ to port(it,"in") width)
 *         ofb-xor       (xor@1: port(it,"in") ⊕ trimmed keystream)
 *       ]
 *     }
 *   ]
 *
 * Like CFB it needs **no new step type** — every leaf already existed — and it
 * needs no counter-advance leaf either: the register advances by being
 * overwritten with the cipher's output, which the iterate's carry already does.
 *
 * ## `chainFeedback` is the UNTRIMMED keystream, deliberately
 *
 * The feedback wire reads the cipher body's output directly, *not*
 * `ofb-trim.output`. On a ragged final block those two differ — the trimmed one
 * is short — and the mode is defined on the full block: `O_j = E(O_{j-1})` with
 * both sides one cipher block wide. Nothing reads the final iteration's
 * feedback, so the two wirings produce byte-identical ciphertext and no test
 * can tell them apart; the full-width wire is still the correct one, and it is
 * what the trace shows a learner.
 *
 * ## The ragged tail
 *
 * As in CTR and CFB, the message may end mid-block and no padding is engaged:
 * the iterate sets `allowPartialFinalBlock`, so the runtime runs
 * `ceil(len / B)` iterations and hands the last one a **short `in` block**, and
 * `ofb-trim` (`truncate-to-reference@1`) cuts the full-width keystream down to
 * match so `xor@1`'s equal-length requirement is met honestly. Ciphertext comes
 * out exactly as long as the plaintext, for any length ≥ 1.
 *
 * **The core stays untouched and cipher-agnostic because the register rides
 * `chain`, not `in`.** `chain` is one full block wide on every iteration, so
 * every core always encrypts a full register and emits full-width keystream;
 * only `in` goes short.
 *
 * ## Scope: full-block OFB only
 *
 * This builds OFB with the full block fed back — the only variant SP 800-38A
 * actually specifies (§6.4 fixes s = b, unlike CFB which it parameterizes), and
 * the one `node:crypto` exposes as `aes-128-ofb`. There is no `-ofb8` to
 * confuse it with.
 *
 * References: NIST SP 800-38A §6.4 (OFB mode definition).
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../../core/types";
import type { BlockCipherCore, CipherDirection } from "../block-cipher-core";
import { port } from "../block-cipher-core";

// Aux key the App seeds the IV under. In OFB the IV is the initial value of the
// output-feedback register O_0 — the block whose encryption produces block 0's
// keystream. Shared with CBC/CTR/CFB rather than growing a parallel channel.
const AUX_IV = "iv";

// The iterate node's id — the per-block dispatch boundary. The runtime injects
// each message block as `port(OFB_ITERATE_ID,"in")` and the feedback register
// as `port(OFB_ITERATE_ID,"chain")`.
const OFB_ITERATE_ID = "ofb-blocks";

// The keystream-XOR leaf id. Held in one place because the KATs pin
// `ofb-xor:b{i}` and it is the spec's output in both directions.
const OFB_XOR_ID = "ofb-xor";
// The ragged-tail trim. A passthrough on every block but a final short one.
const OFB_TRIM_ID = "ofb-trim";

/**
 * Initial-register narration. Block size is interpolated from the core because
 * the feedback register is exactly one cipher block wide.
 */
const narrFetchIv = (core: BlockCipherCore): StepDocumentation => ({
  name: "Load IV (initial output-feedback register)",
  summary: `Read the ${core.blockByteLength}-byte IV from aux — OFB's initial register O₀, the seed of the whole keystream (NIST SP 800-38A §6.4).`,
  detail: `## Load IV (O₀)

Reads the initialization vector from \`aux["iv"]\` and publishes it on a port so
the first iteration can encrypt it. In OFB the IV is the starting value of the
**output-feedback register**, and every keystream block after the first is
produced by encrypting the one before it:

\`\`\`
O₁ = E(IV)      O₂ = E(O₁)      O₃ = E(O₂)   …
\`\`\`

So this single value determines the *entire* keystream. Nothing else feeds it —
not the plaintext, not the ciphertext. Change one byte here and every block of
output changes.

That is also why an OFB IV must **never** be reused with the same key: two
messages encrypted under the same (key, IV) pair get byte-for-byte the same
keystream, and XORing the two ciphertexts together cancels it out entirely,
leaving the two plaintexts XORed with each other. The IV is not secret — it
travels alongside the ciphertext — but it must be fresh.`,
  references: ["NIST SP 800-38A §6.4 (OFB)", "NIST SP 800-38A Appendix C (IV generation)"],
});

/**
 * Keystream-XOR narration. Direction-aware prose over an operation that is not
 * merely identical between the directions but comes from a byte-identical spec
 * — which is the point this prose exists to make.
 */
const narrOfbXor = (core: BlockCipherCore, isDecrypt: boolean): StepDocumentation => ({
  name: "Keystream XOR (OFB)",
  summary: isDecrypt
    ? "XOR the ciphertext block with the keystream block to recover plaintext — the same operation, from the same keystream, that encrypted it."
    : "XOR the plaintext block with the keystream block to produce ciphertext.",
  detail: `## Keystream XOR (${isDecrypt ? "decrypt" : "encrypt"})

The register \`O_{i}\` has just been run through ${core.familyName} to produce one block of
**keystream**. This step XORs that keystream with the message block:

\`\`\`
${isDecrypt ? "P_i = C_i ⊕ O" : "C_i = P_i ⊕ O"}_{i+1}
\`\`\`

${
  isDecrypt
    ? `The encrypt side computes \`C_i = P_i ⊕ O_{i+1}\` — the **same formula over the same
keystream**, because XOR is its own inverse. The ${core.familyName} box above is running
*forwards* even though this spec decrypts; OFB never invokes the inverse
cipher.`
    : `Note what did **not** enter the cipher: the plaintext. ${core.familyName} only ever sees the
feedback register. The message meets nothing but this XOR, which is what turns a
block cipher into a stream cipher.`
}

## The keystream owes nothing to the message

This is what separates OFB from CFB. CFB refills its register from the previous
**ciphertext**, so its keystream depends on the message. OFB refills its
register from the cipher's **own output**, so the keystream depends only on the
key and the IV.

Three things follow, all visible in this trace:

- **It could have been computed in advance.** Every keystream block above this
  one could have been generated before the plaintext existed.
- **It cannot be jumped into.** Reaching block *n* means performing *n*
  encryptions in sequence — each register is the last one's output. CTR reaches
  block *n* by adding *n* to its counter and encrypting once, which is why CTR
  is the mode in use today.
- **Errors do not spread.** Flip a bit of this block's ciphertext and exactly
  that bit of plaintext flips. No later block is touched, because no later
  register ever sees the ciphertext. Run the same experiment in CFB and the
  damage covers this block and all of the next.

## Encrypt and decrypt are the same spec

Because the keystream is message-independent, the two directions here are not
merely similar — they are structurally identical, differing only in name. CFB
cannot say that: its register must hold the ciphertext, and which port carries
the ciphertext flips with direction.`,
  references: ["NIST SP 800-38A §6.4 (OFB-Encrypt / OFB-Decrypt)"],
});

/**
 * Ragged-tail trim narration. Type-prose only — the per-frame value-prose
 * (which bytes were discarded) comes from the registered narrator for
 * `truncate-to-reference@1` in `src/ui/narration/truncate.tsx`, which can
 * branch on the real widths as this static block cannot.
 */
const narrOfbTrim = (core: BlockCipherCore): StepDocumentation => ({
  name: "Trim keystream to block (OFB)",
  summary:
    "Cuts the keystream down to the message block's width, so a message that ends mid-block needs no padding.",
  detail: `## Trim keystream to block

${core.familyName} always produces a full ${core.blockByteLength}-byte block of keystream — it knows
no other size. But the *last* block of a message need not be that long: in
output-feedback mode a message is not required to end on a block boundary.

This step keeps as many keystream bytes as the message block actually has and
discards the rest, so the XOR below gets two operands of equal length. On every
block except a final short one it does nothing.

## What is NOT trimmed

The bytes discarded here are dropped from the copy heading into the XOR only.
The **feedback register** is refilled from the cipher's full ${core.blockByteLength}-byte output,
not from this trimmed copy — \`O_j = E(O_{j-1})\` is defined on whole blocks.
(On a final short block nothing reads the register again, so this makes no
difference to the output; it is drawn honestly because it is what the mode
says.)

## Why this is the step that makes OFB padding-free

ECB and CBC push each block **through** the cipher, and a block cipher has no
meaning for a partial block — which is why those modes must pad first.

OFB never feeds the message to the cipher; only the register goes in, and that
register is always a full ${core.blockByteLength} bytes wide. The message meets nothing but an XOR,
so it can stop wherever it likes and the ciphertext comes out **exactly as long
as the plaintext**. Trimming the keystream — rather than padding the message —
is the honest depiction of that: no invented plaintext byte ever enters the
computation.`,
  references: ["NIST SP 800-38A §6.4 (OFB mode — the final partial block)"],
});

/** aux["iv"] (one block wide) → port output. The initial register O₀. */
const fetchIvLeaf = (core: BlockCipherCore): StepNode => ({
  kind: "step",
  id: "fetch-iv",
  type: "aux-load-bytes@1",
  params: { auxName: AUX_IV, byteLength: core.blockByteLength },
  narrationOverride: narrFetchIv(core),
});

/**
 * Build the OFB spec for any block cipher.
 *
 * @param core      the block cipher whose FORWARD body generates the keystream —
 *                  `buildDecryptBody` is never called, in either direction
 * @param direction affects the spec id, name, and prose — and, uniquely among
 *                  the chaining modes, **nothing structural at all**. OFB's
 *                  keystream is message-independent, so both directions are the
 *                  same wiring. Compare `modes/cfb.ts`, whose two directions
 *                  differ in which port refills the register.
 */
export function buildOfbSpec(core: BlockCipherCore, direction: CipherDirection): CipherSpec {
  const isDecrypt = direction === "decrypt";

  const blockIn = port(OFB_ITERATE_ID, "in"); // the per-block message bytes
  const registerIn = port(OFB_ITERATE_ID, "chain"); // O_i, carried across iterations

  // The FORWARD cipher, seeded from the feedback REGISTER — not from the
  // message block. As in CTR and CFB, `in` never reaches the cipher at all.
  const keystream = core.buildEncryptBody(registerIn);

  // Trim the full-width keystream down to THIS block's width. `reference` is
  // the message block itself — only its length is read.
  const ofbTrim: StepNode = {
    kind: "step",
    id: OFB_TRIM_ID,
    type: "truncate-to-reference@1",
    params: {},
    portInputs: { input: keystream.output, reference: blockIn },
    narrationOverride: narrOfbTrim(core),
  };

  // Message block ⊕ trimmed keystream.
  const ofbXor: StepNode = {
    kind: "step",
    id: OFB_XOR_ID,
    type: "xor@1",
    params: { inputCount: 2 },
    portInputs: { operand0: blockIn, operand1: port(OFB_TRIM_ID, "output") },
    narrationOverride: narrOfbXor(core, isDecrypt),
  };

  const specId = `${core.id}-ofb${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${core.displayName} OFB${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: OFB_ITERATE_ID,
    label: `OFB blocks (${core.familyName} keystream ⊕ message, register ← keystream)`,
    seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    blockByteLength: core.blockByteLength,
    // The ragged tail: the message may end mid-block, and the final iteration
    // then receives a SHORT `in` block which `ofb-trim` matches the keystream
    // to. ECB/CBC leave this absent and keep the whole-multiple requirement.
    allowPartialFinalBlock: true,
    // The carry holds the output-feedback register: bootstrapped from the IV,
    // then overwritten with each keystream block.
    chainInput: port("fetch-iv", "output"),
    // THE line that defines OFB, and the only wire that distinguishes it from
    // CFB: the register is refilled from the CIPHER'S OWN OUTPUT. Deliberately
    // `keystream.output` (full width B) rather than the trimmed copy — see the
    // file header. There is no direction branch here, because the keystream
    // does not depend on the message.
    chainFeedback: keystream.output,
    bodyOutput: port(OFB_XOR_ID, "output"),
    outputPorts: ["out"],
    children: [...keystream.nodes, ofbTrim, ofbXor],
  };

  return {
    id: specId,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      // As in CBC/CTR/CFB, the App seeds `aux["iv"]` alongside `aux["key"]`;
      // here the IV field's bytes are the initial feedback register.
      key: { byteLength: core.keyByteLength },
    },
    steps: [
      // Key expansion runs once, outside the loop — its round keys reach every
      // iteration through the global aux map.
      core.buildKeySchedule(),
      // O₀ → a port the iterate's `chainInput` reads.
      fetchIvLeaf(core),
      iterateNode,
    ],
    outputFrom: port(OFB_ITERATE_ID, "out"),
  };
}
