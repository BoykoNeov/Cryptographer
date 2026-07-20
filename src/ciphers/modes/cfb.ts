/**
 * CFB (Cipher Feedback) — the mode of operation, written once for every block
 * cipher.
 *
 * CFB is the mode that sits between CBC and CTR, and it is worth building
 * precisely because it borrows one half from each:
 *
 *   C_i = P_i ⊕ E_K(S_i)      S_0 = the IV,  S_{i+1} = C_i
 *
 *  - **From CTR** it takes the keystream idea: the cipher encrypts a *feedback
 *    register*, never the message, and the message only ever meets an XOR. So
 *    the FORWARD cipher runs in both directions, the inverse body is never
 *    invoked, and no padding is required.
 *  - **From CBC** it takes the chain: the feedback register holds the previous
 *    **ciphertext** block, so the blocks are serially dependent (unlike CTR,
 *    nothing here can be computed out of order) and identical plaintext blocks
 *    still encrypt differently.
 *
 * That combination makes CFB a **self-synchronizing** stream cipher: because
 * the register is filled from the ciphertext — which both parties can see — a
 * receiver who loses their place recovers after one full block.
 *
 * ## The one structural difference between encrypt and decrypt
 *
 * Both directions run the same three leaves in the same order, and both emit
 * the XOR's output. They differ in **one line**: what feeds the chain.
 *
 * **Encrypt** (`C_i = P_i ⊕ E(S_i)`):
 *   bodyOutput    = cfb-xor.output      (= C_i)
 *   chainFeedback = cfb-xor.output      (= C_i)   // the ciphertext we EMIT
 *
 * **Decrypt** (`P_i = C_i ⊕ E(S_i)`):
 *   bodyOutput    = cfb-xor.output      (= P_i)
 *   chainFeedback = port(it,"in")       (= C_i)   // the ciphertext that ARRIVED
 *
 * The register must always hold the *ciphertext*, and which port carries the
 * ciphertext flips with direction: on encrypt it is what leaves, on decrypt it
 * is what arrives. This is exactly CBC's asymmetry (see `modes/cbc.ts`), and it
 * is why this builder is templated on CBC rather than on CTR — CTR's "encrypt
 * and decrypt are the same spec" is the one property CFB does *not* share,
 * despite the shared keystream shape. A CFB decrypt that fed back its own
 * output would still round-trip against its own encrypt while disagreeing with
 * every real implementation.
 *
 * `chainFeedback = port(it,"in")` resolves because the runtime seeds the body
 * scope's node-output map with the injected `in`/`chain` ports and they survive
 * the body walk (see `runtime.ts` `walk`).
 *
 * The shape it builds:
 *
 *   [
 *     <core key schedule>  (aux-only — publishes round keys once, before the loop)
 *     fetch-iv             (aux-load-bytes@1 — reads aux["iv"] = the initial register S_0)
 *     iterate "cfb-blocks" {
 *       seedInput:     $input                       // the message bytes
 *       blockByteLength: core.blockByteLength
 *       allowPartialFinalBlock: true                // the ragged tail (below)
 *       chainInput:    port(fetch-iv,"output")      // S_0 = IV bootstraps the register
 *       chainFeedback: <direction-dependent — see above>
 *       bodyOutput:    port(cfb-xor,"output")
 *       outputPorts:   ["out"]
 *       children: [
 *         <core FORWARD body, seeded from port(it,"chain")>  → keystream E(S_i)
 *         cfb-trim      (truncate-to-reference@1: keystream ↓ to port(it,"in") width)
 *         cfb-xor       (xor@1: port(it,"in") ⊕ trimmed keystream)
 *       ]
 *     }
 *   ]
 *
 * Note there is no counter-advance leaf: CFB's register advances by being
 * *overwritten* with the ciphertext, which the iterate's carry already does.
 * That is why this mode needed no new step type at all — every leaf it uses
 * already existed for CBC and CTR.
 *
 * ## The ragged tail
 *
 * As in CTR, the message may end mid-block and no padding is engaged: the
 * iterate sets `allowPartialFinalBlock`, so the runtime runs `ceil(len / B)`
 * iterations and hands the last one a **short `in` block**, and `cfb-trim`
 * (`truncate-to-reference@1`) cuts the full-width keystream down to match so
 * `xor@1`'s equal-length requirement is met honestly. Ciphertext comes out
 * exactly as long as the plaintext, for any length ≥ 1.
 *
 * **The core stays untouched and cipher-agnostic because the register rides
 * `chain`, not `in`.** `chain` is one full block wide on every iteration (the
 * IV, then a full ciphertext block), so every core always encrypts a full
 * register and emits full-width keystream; only `in` goes short. The final
 * iteration's `chainFeedback` may be short, but it is the last — nothing reads
 * it.
 *
 * ## Scope: full-block CFB only
 *
 * This builds **CFB-b where b = the full block width** (CFB128 for AES, CFB64
 * for DES/Blowfish) — the variant NIST SP 800-38A §6.3 parameterizes with
 * `s = b`, and the one `node:crypto` exposes as `aes-128-cfb`. The narrow-shift
 * variants (CFB8, CFB1) re-key the cipher once per byte or per bit and shift
 * the register rather than replacing it; that does not fit the block-at-a-time
 * iterate this mode machine is built on, and is deliberately out of scope.
 *
 * References: NIST SP 800-38A §6.3 (CFB mode definition).
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../../core/types";
import type { BlockCipherCore, CipherDirection } from "../block-cipher-core";
import { port } from "../block-cipher-core";

// Aux key the App seeds the IV under. In CFB the IV is the initial value of the
// feedback register S_0 — the block that gets encrypted to make block 0's
// keystream. Shared with CBC/CTR rather than growing a parallel channel.
const AUX_IV = "iv";

// The iterate node's id — the per-block dispatch boundary. The runtime injects
// each message block as `port(CFB_ITERATE_ID,"in")` and the feedback register
// as `port(CFB_ITERATE_ID,"chain")`.
const CFB_ITERATE_ID = "cfb-blocks";

// The keystream-XOR leaf id. Held in one place because the KATs pin
// `cfb-xor:b{i}` and both directions emit from it.
const CFB_XOR_ID = "cfb-xor";
// The ragged-tail trim. A passthrough on every block but a final short one.
const CFB_TRIM_ID = "cfb-trim";

/**
 * Initial-register narration. Block size is interpolated from the core because
 * the feedback register is exactly one cipher block wide.
 */
const narrFetchIv = (core: BlockCipherCore): StepDocumentation => ({
  name: "Load IV (initial feedback register)",
  summary: `Read the ${core.blockByteLength}-byte IV from aux — CFB's initial feedback register S₀ (NIST SP 800-38A §6.3).`,
  detail: `## Load IV (S₀)

Reads the initialization vector from \`aux["iv"]\` and publishes it on a port so
the first iteration can encrypt it. In CFB the IV is the starting value of the
**feedback register**: the block that gets encrypted to produce block 0's
keystream.

From block 1 onward the register is not computed but simply *overwritten* with
the previous ciphertext block. The IV exists only because block 0 has no
previous ciphertext to use.

Unlike CBC's IV, this value is never XORed with anything — it goes straight
into the cipher, exactly as CTR's counter does. Editing it changes block 0's
keystream, and because that changes block 0's ciphertext, the change cascades
into every block after it.

The IV must be unpredictable per message, but it is **not** secret — it travels
alongside the ciphertext.`,
  references: ["NIST SP 800-38A §6.3 (CFB)", "NIST SP 800-38A Appendix C (IV generation)"],
});

/**
 * Keystream-XOR narration. Direction-aware prose over an identical operation —
 * and, as in CTR, the point is that it IS identical. What differs between the
 * directions is only which port refills the register, which this prose names.
 */
const narrCfbXor = (core: BlockCipherCore, isDecrypt: boolean): StepDocumentation => ({
  name: "Keystream XOR (CFB)",
  summary: isDecrypt
    ? "XOR the ciphertext block with the encrypted feedback register to recover plaintext — the same operation that encrypted it."
    : "XOR the plaintext block with the encrypted feedback register to produce ciphertext.",
  detail: `## Keystream XOR (${isDecrypt ? "decrypt" : "encrypt"})

The feedback register \`S_i\` has just been run through ${core.familyName} to produce one block
of **keystream**. This step XORs that keystream with the message block:

\`\`\`
${isDecrypt ? "P_i = C_i ⊕ " : "C_i = P_i ⊕ "}${core.familyName}_encrypt(S_i)
\`\`\`

${
  isDecrypt
    ? `Compare that with the encrypt side: \`C_i = P_i ⊕ ${core.familyName}_encrypt(S_i)\`. It is the
**same formula**, because XOR is its own inverse — so the ${core.familyName} box above is
running *forwards* even though this spec decrypts. CFB never invokes the
inverse cipher, which is why a cipher only needs a forward direction to be
usable in this mode.`
    : `Note what did **not** enter the cipher: the plaintext. ${core.familyName} only ever sees the
feedback register. The message is combined with the result afterwards, which is
what turns a block cipher into a stream cipher — and why decryption runs this
exact same forward path rather than an inverse.`
}

## What refills the register

CFB's register must hold the previous **ciphertext** block. ${
    isDecrypt
      ? `On decrypt the ciphertext is what *arrives*, so the register is refilled from
this iteration's raw input block — not from the plaintext this step just
produced.`
      : `On encrypt the ciphertext is what *leaves*, so the register is refilled from
this step's own output.`
  }

That is the single structural difference between CFB's encrypt and decrypt
specs; every leaf and every wire besides that one is identical.

## Where the chaining shows

Because the register is the previous ciphertext, blocks are **serially
dependent**: block \`i\`'s keystream cannot be computed until block \`i-1\`'s
ciphertext exists. This is CFB's inheritance from CBC, and the clearest
contrast with CTR — whose counter is known in advance, so every block there is
independent.`,
  references: ["NIST SP 800-38A §6.3 (CFB-Encrypt / CFB-Decrypt)"],
});

/**
 * Ragged-tail trim narration. Type-prose only — the per-frame value-prose
 * (which bytes were discarded) comes from the registered narrator for
 * `truncate-to-reference@1` in `src/ui/narration/truncate.tsx`, which can
 * branch on the real widths as this static block cannot.
 */
const narrCfbTrim = (core: BlockCipherCore): StepDocumentation => ({
  name: "Trim keystream to block (CFB)",
  summary:
    "Cuts the keystream down to the message block's width, so a message that ends mid-block needs no padding.",
  detail: `## Trim keystream to block

${core.familyName} always produces a full ${core.blockByteLength}-byte block of keystream — it knows
no other size. But the *last* block of a message need not be that long: in
cipher-feedback mode a message is not required to end on a block boundary.

This step keeps as many keystream bytes as the message block actually has and
discards the rest, so the XOR below gets two operands of equal length. On every
block except a final short one it does nothing.

## Why this is the step that makes CFB padding-free

ECB and CBC push each block **through** the cipher, and a block cipher has no
meaning for a partial block — which is why those modes must pad first.

CFB never feeds the message to the cipher; only the feedback register goes in,
and that register is always a full ${core.blockByteLength} bytes wide. The message meets nothing
but an XOR, so it can stop wherever it likes and the ciphertext comes out
**exactly as long as the plaintext**. Trimming the keystream — rather than
padding the message — is the honest depiction of that: no invented plaintext
byte ever enters the computation.`,
  references: ["NIST SP 800-38A §6.3 (CFB mode — the final partial block)"],
});

/** aux["iv"] (one block wide) → port output. The initial feedback register S₀. */
const fetchIvLeaf = (core: BlockCipherCore): StepNode => ({
  kind: "step",
  id: "fetch-iv",
  type: "aux-load-bytes@1",
  params: { auxName: AUX_IV, byteLength: core.blockByteLength },
  narrationOverride: narrFetchIv(core),
});

/**
 * Build the CFB spec for any block cipher.
 *
 * @param core      the block cipher whose FORWARD body generates the keystream —
 *                  `buildDecryptBody` is never called, in either direction
 * @param direction affects the spec id, name, prose, and — the one structural
 *                  difference — which port refills the feedback register
 */
export function buildCfbSpec(core: BlockCipherCore, direction: CipherDirection): CipherSpec {
  const isDecrypt = direction === "decrypt";

  const blockIn = port(CFB_ITERATE_ID, "in"); // the per-block message bytes
  const registerIn = port(CFB_ITERATE_ID, "chain"); // S_i, carried across iterations

  // The FORWARD cipher, seeded from the feedback REGISTER — not from the
  // message block. As in CTR, `in` never reaches the cipher at all.
  const keystream = core.buildEncryptBody(registerIn);

  // Trim the full-width keystream down to THIS block's width. `reference` is
  // the message block itself — only its length is read.
  const cfbTrim: StepNode = {
    kind: "step",
    id: CFB_TRIM_ID,
    type: "truncate-to-reference@1",
    params: {},
    portInputs: { input: keystream.output, reference: blockIn },
    narrationOverride: narrCfbTrim(core),
  };

  // Message block ⊕ trimmed keystream. Identical in both directions.
  const cfbXor: StepNode = {
    kind: "step",
    id: CFB_XOR_ID,
    type: "xor@1",
    params: { inputCount: 2 },
    portInputs: { operand0: blockIn, operand1: port(CFB_TRIM_ID, "output") },
    narrationOverride: narrCfbXor(core, isDecrypt),
  };

  // THE line that differs between the directions. The register must hold the
  // ciphertext block; on encrypt that is what we emit, on decrypt it is what
  // arrived. See the file header — getting this wrong still round-trips
  // against itself, so it is pinned by the KATs against an external oracle.
  const chainFeedback: PortBinding = isDecrypt ? blockIn : port(CFB_XOR_ID, "output");

  const specId = `${core.id}-cfb${isDecrypt ? "-decrypt" : ""}@1`;
  const name = `${core.displayName} CFB${isDecrypt ? " (decrypt)" : ""}`;

  const iterateNode: StepNode = {
    kind: "iterate",
    id: CFB_ITERATE_ID,
    label: `CFB blocks (${core.familyName} keystream ⊕ message, register ← ciphertext)`,
    seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    blockByteLength: core.blockByteLength,
    // The ragged tail: the message may end mid-block, and the final iteration
    // then receives a SHORT `in` block which `cfb-trim` matches the keystream
    // to. ECB/CBC leave this absent and keep the whole-multiple requirement.
    allowPartialFinalBlock: true,
    // The carry holds the feedback register: bootstrapped from the IV, then
    // overwritten with each ciphertext block.
    chainInput: port("fetch-iv", "output"),
    chainFeedback,
    bodyOutput: port(CFB_XOR_ID, "output"),
    outputPorts: ["out"],
    children: [...keystream.nodes, cfbTrim, cfbXor],
  };

  return {
    id: specId,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      // As in CBC/CTR, the App seeds `aux["iv"]` alongside `aux["key"]`; here
      // the IV field's bytes are the initial feedback register.
      key: { byteLength: core.keyByteLength },
    },
    steps: [
      // Key expansion runs once, outside the loop — its round keys reach every
      // iteration through the global aux map.
      core.buildKeySchedule(),
      // S₀ → a port the iterate's `chainInput` reads.
      fetchIvLeaf(core),
      iterateNode,
    ],
    outputFrom: port(CFB_ITERATE_ID, "out"),
  };
}
