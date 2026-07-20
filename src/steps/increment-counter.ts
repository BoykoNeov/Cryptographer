/**
 * Increment counter — port-native big-endian counter increment, the one
 * primitive CTR mode needs that no existing step supplies.
 *
 * Reads the `counter` port (a flat `Uint8Array` of any length), produces
 * `output` = the same value plus one, interpreted as a **big-endian unsigned
 * integer** and wrapping modulo 2^(8·length). One-in one-out, no params.
 *
 * ## Why a dedicated step type
 *
 * CTR turns a block cipher into a stream cipher by encrypting a *counter*
 * block per message block: `C_i = P_i ⊕ E(T_i)`, where `T_{i+1} = T_i + 1`
 * (NIST SP 800-38A §6.5). Something has to compute that `+1`, and nothing in
 * the vocabulary does:
 *
 *   - `add-mod-32@1` / `add-mod-16@1` are fixed-WIDTH word adders. A counter
 *     block is one cipher block wide — 16 bytes for AES, 8 for DES/Blowfish,
 *     4 for Speck32/64 — so a 32-bit adder is simultaneously too narrow for
 *     AES and too wide for Speck. Carry must propagate across the WHOLE block.
 *   - Composing it from narrower adders would need per-core wiring (four
 *     32-bit adds with carry for AES, one for Speck), which is exactly the
 *     per-cipher branching the cipher-agnostic mode machine exists to delete.
 *
 * So the width is not a param — it is **derived from the input port's byte
 * length**. That is what lets `modes/ctr.ts` drop one `increment-counter@1`
 * leaf into the loop and have it be correct for every `BlockCipherCore`,
 * whatever its block size. The step's block-size genericity is the mode's
 * block-size genericity.
 *
 * ## Big-endian, and wrapping
 *
 * Big-endian because that is the standard counter convention: SP 800-38A's
 * "standard incrementing function" treats the rightmost bits as the counter,
 * so the carry travels right-to-left. This matches `node:crypto`'s
 * `aes-128-ctr`, which is the KAT oracle.
 *
 * Wrapping (mod 2^(8·len)) rather than throwing on overflow: an all-`0xFF`
 * counter block increments to all-zero. Real CTR *must* never reach that point
 * with the same key (the keystream would repeat), but that is a key-management
 * property, not something this leaf can police — it sees one block, not the
 * message length. Wrapping keeps the arithmetic honest and total.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`, omit
 * `shapeContract`. Static `PortContract` on both sides (one fixed port each) —
 * the "function form only when N varies on THIS side" rule from Slice 2.1b.
 *
 * References: NIST SP 800-38A §6.5 + Appendix B.1 (CTR mode, the standard
 * incrementing function).
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Port contract + executor ─────────────────────────────────────────────

export const incrementCounterPortContract: PortContract = {
  // Polymorphic byteLength on both ports — the wired source determines the
  // width, and the width IS the counter's modulus. `layout: "raw"`: the bytes
  // are one integer, not a structured block.
  inputs: new Map([["counter", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const incrementCounter: PortedExecutor = (inputs, _params, _ctx) => {
  const counter = inputs.get("counter");
  if (counter === undefined) {
    throw new Error("increment-counter: missing required input port 'counter'");
  }
  if (counter.length === 0) {
    // A zero-width counter has no representable value to increment. Fail loud
    // rather than silently returning an empty block that a downstream XOR
    // would then reject with a confusing length-mismatch message.
    throw new Error("increment-counter: 'counter' port must be at least 1 byte wide");
  }

  // Fresh buffer — the runtime treats outputs as freshly-owned arrays, and the
  // CTR loop's chain carry reads this while the input block is still live.
  const out = new Uint8Array(counter);

  // Ripple the carry from the least-significant (rightmost) byte leftward.
  // A byte that wraps 0xFF → 0x00 carries into its neighbour; the first byte
  // that does NOT wrap stops the ripple. If every byte wraps, the whole
  // counter wraps to zero (mod 2^(8·length)) — see the header.
  for (let i = out.length - 1; i >= 0; i--) {
    const incremented = ((out[i] as number) + 1) & 0xff;
    out[i] = incremented;
    if (incremented !== 0) break; // no carry out of this byte — done
  }

  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const incrementCounterDoc: StepDocumentation = {
  name: "Increment counter",
  summary:
    "Adds one to the input, read as a big-endian number spanning the whole block. Wraps around to zero on overflow.",
  detail: `# Increment counter

Adds **one** to the input bytes, treating the entire block as a single
big-endian unsigned number: the last byte is the least significant, and a carry
ripples leftward.

\`\`\`
00 00 00 01  →  00 00 00 02
00 00 00 FF  →  00 00 01 00      (the carry moves left)
FF FF FF FF  →  00 00 00 00      (wraps around)
\`\`\`

The output is always the same length as the input, and the counter's width is
whatever that length happens to be — there is no width setting. That is
deliberate: a counter block is exactly one cipher block wide, which is 16 bytes
for AES or Serpent, 8 for DES or Blowfish, and 4 for Speck32/64. Deriving the
width from the wiring is what lets the *same* step work inside every cipher's
CTR loop.

## Where it fits

**CTR mode** (counter mode) turns a block cipher into a stream cipher. Instead
of encrypting the message, it encrypts a counter to make a **keystream**, then
XORs that keystream with the message:

\`\`\`
C_i = P_i ⊕ E(T_i)      where  T_{i+1} = T_i + 1
\`\`\`

This step is the \`+ 1\`. Each block advances the counter so the next block gets
a *different* keystream block — which is the whole point. If the counter never
changed, every block would be XORed with the same keystream, and two ciphertext
blocks XORed together would reveal the two plaintexts XORed together.

Counting up from the initial value means the same key must never be reused with
the same starting counter: the keystream would repeat exactly, and that is the
one thing CTR cannot survive. That is why CTR needs a fresh nonce per message.`,
  params: new Map(),
  references: [
    "NIST SP 800-38A §6.5 (CTR mode)",
    "NIST SP 800-38A Appendix B.1 (the standard incrementing function)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
