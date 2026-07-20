/**
 * Truncate to reference — keep the leading bytes of one port, as many as a
 * SECOND port is wide. The primitive CTR's ragged tail needs, and the one that
 * makes "the ciphertext is exactly as long as the plaintext" true.
 *
 * Reads `input` (the full-width value) and `reference` (whose *length* is the
 * target — its bytes are never read), produces `output` =
 * `input[0 .. reference.length]`. Two in, one out, no params.
 *
 * ## Why the length cannot be a param
 *
 * CTR turns a block cipher into a stream cipher: it encrypts a counter to make
 * keystream and XORs that keystream with the message (NIST SP 800-38A §6.5).
 * Because the message never enters the cipher, a message that ends mid-block
 * needs only as many keystream bytes as it has message bytes — CTR requires no
 * padding, and that is one of the three headline facts the mode exists to
 * teach.
 *
 * The final block's width is therefore `messageLength mod blockSize`, which is
 * a property of the *message the user typed*, not of the spec. It changes on
 * every keystroke. So `byte-slice@1` cannot serve: its `length` is a param,
 * fixed when the spec is authored. Here the width is only knowable at run
 * time, and the honest way to express "as wide as that value over there" is to
 * wire the value itself and read its length.
 *
 * That is the same rationale as `increment-counter@1`'s — the width is not a
 * setting, it is the wiring — and it is what keeps `modes/ctr.ts`
 * cipher-agnostic. One `truncate-to-reference@1` leaf is correct for every
 * `BlockCipherCore`, whatever its block size, and correct for every message
 * length including the ones that divide evenly (where it is a no-op
 * passthrough).
 *
 * ## Why trimming the KEYSTREAM, not the output
 *
 * The leaf sits *inside* the per-block loop, between the cipher body and the
 * XOR, and trims the keystream down to the message block's width. It does not
 * trim the final concatenated ciphertext. The distinction is pedagogical: the
 * alternative (zero-pad the message, trim at the end) makes a padded plaintext
 * block visibly enter the XOR, which contradicts the very claim CTR is here to
 * demonstrate. Trimming the keystream shows the truth — the short block was
 * short the whole way through.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`, omit
 * `shapeContract`. Static `PortContract` on both sides (fixed port count) —
 * the "function form only when N varies on THIS side" rule from Slice 2.1b.
 *
 * References: NIST SP 800-38A §6.5 (CTR mode — the final partial block).
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Port contract + executor ─────────────────────────────────────────────

export const truncateToReferencePortContract: PortContract = {
  // Polymorphic byteLength on every port — `input`'s width comes from the
  // cipher's block size, `reference`'s from the message, and `output`'s is
  // `reference`'s. `layout: "raw"`: flat bytes, no structured reading.
  inputs: new Map([
    ["input", { layout: "raw" }],
    ["reference", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const truncateToReference: PortedExecutor = (inputs, _params, _ctx) => {
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error("truncate-to-reference: missing required input port 'input'");
  }
  const reference = inputs.get("reference");
  if (reference === undefined) {
    throw new Error("truncate-to-reference: missing required input port 'reference'");
  }

  // Widening is not truncation — there are no bytes to invent. This fires when
  // a spec wires the two ports backwards, and naming both widths turns an
  // otherwise baffling downstream length mismatch into a located bug.
  if (reference.length > input.length) {
    throw new Error(
      `truncate-to-reference: 'reference' (${reference.length} bytes) is wider than 'input' (${input.length} bytes) — this step can only shorten, never extend`,
    );
  }

  // Fresh buffer, not a `subarray` view: the runtime treats step outputs as
  // freshly-owned arrays, and a view would alias the keystream block that the
  // trace has already snapshotted.
  return new Map([["output", new Uint8Array(input.subarray(0, reference.length))]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const truncateToReferenceDoc: StepDocumentation = {
  name: "Truncate to reference",
  summary:
    "Keeps the first N bytes of the input, where N is however wide the reference value is. Discards the rest.",
  detail: `# Truncate to reference

Keeps the **leading bytes** of \`input\` — as many as the \`reference\` port is
wide — and discards the remainder.

\`\`\`
input      A1 B2 C3 D4 E5 F6 07 18     (8 bytes)
reference  ?? ?? ?? ??                 (4 bytes — only its LENGTH matters)
output     A1 B2 C3 D4                 (the first 4)
\`\`\`

The reference value's *bytes are never read*. It is wired in purely so this
step can measure it. When the two are already the same width the step is a
passthrough — the input emerges unchanged.

There is no length setting. That is deliberate, and it is the whole point:
the width this step trims to is not known when the cipher is authored, only
when someone types a message. Wiring the value whose length you want is the
honest way to say "as wide as that."

## Where it fits

**CTR mode** turns a block cipher into a stream cipher. It never encrypts the
message — it encrypts a *counter* to manufacture a **keystream**, then XORs
that keystream with the message:

\`\`\`
C_i = P_i ⊕ E(T_i)
\`\`\`

Because the message only ever meets an XOR, it does not need to fill a whole
block. A 5-byte message wants exactly 5 keystream bytes. **This is why CTR
needs no padding at all** — unlike ECB and CBC, which push each block *through*
the cipher and so must first top it up to a full block.

The cipher still produces a whole block of keystream, though; it knows no other
size. This step is what reconciles those two facts. On the final block of a
message that ends mid-block, it keeps as many keystream bytes as there are
message bytes and throws the rest away — so the XOR gets two equal-length
operands, and the ciphertext comes out **exactly as long as the plaintext**.

On every earlier block, and on every block of a message that happens to divide
evenly, it does nothing at all.`,
  params: new Map(),
  references: ["NIST SP 800-38A §6.5 (CTR mode)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
