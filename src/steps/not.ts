/**
 * Not — port-native bitwise NOT primitive (universal-port plan Phase 2
 * Slice 2.3, 2026-05-24).
 *
 * Single-input single-output: reads `input` port (a flat `Uint8Array`
 * of any length), produces `output` port with every byte's bits
 * inverted. The simplest possible port-native step — no params, no
 * state, no aux. Same posture as `rotate-bits-right@1` (Slice 2.1a)
 * minus the param dispatch.
 *
 * **Why this is its own step type.** SHA-256's Ch function reads
 * \`(x ∧ y) ⊕ (¬x ∧ z)\` (FIPS 180-4 §4.1.2). With \`and@1\`
 * (this slice) and \`xor@1\` (Slice 2.1b) shipped, the missing
 * primitive is \`not@1\`. The alternative — expressing NOT as
 * \`xor@1\` against a constant all-ones operand wired from \`aux-load\`
 * — works algebraically but obscures intent in both the spec and the
 * graph view; a dedicated step type names the operation, lets
 * narration call it "complement," and keeps the SHA-256 graph
 * one-leaf-per-conceptual-step.
 *
 * **Why no params.** There's no width parameter (NOT operates bit-by-
 * bit; the byte-width interpretation handles any input length) and no
 * arity parameter (NOT is strictly 1-in 1-out). The port-native
 * contract handles "any length" via the polymorphic `byteLength` on
 * the input port. Future variants — e.g., a fixed-width-aware NOT that
 * masks the result to a declared word width — would be a separate
 * step type, not a param on this one.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. PortContract is fully static — both sides
 * have one fixed port (`input` / `output`); function form is overkill
 * here (Slice 2.1b's "function form only when N varies on THIS side"
 * rule).
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Port contract + executor ─────────────────────────────────────────────

export const notPortContract: PortContract = {
  // Polymorphic byteLength on both ports — wiring at the consumer
  // determines the actual length, validated nowhere (NOT works on any
  // length). `layout: "raw"` because no UI surface in Phase 2's scope
  // reads layout-as-data; per the Slice 2.2 pinned principle, layout
  // tags appear when a consumer needs them.
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const not: PortedExecutor = (inputs, _params, _ctx) => {
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error("not: missing required input port 'input'");
  }
  // Allocate a fresh output buffer — the runtime treats outputs as
  // freshly-owned arrays; mutating the input in place would couple
  // downstream effects back to the wired source. ~ on a number forces
  // a 32-bit signed two's-complement flip; `& 0xff` re-clamps to a
  // byte. Equivalent to `255 - x` but reads as "bitwise complement."
  const out = new Uint8Array(inputBytes.length);
  for (let i = 0; i < inputBytes.length; i++) {
    out[i] = ~(inputBytes[i] as number) & 0xff;
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const notDoc: StepDocumentation = {
  name: "NOT",
  summary: "Flips every bit of the input — each 0 becomes 1 and each 1 becomes 0.",
  detail: `# NOT

Inverts every bit of the input: each 0 becomes a 1 and each 1 becomes a 0.
The output is the same length as the input. Also called the bitwise
**complement**.

## Math

For each byte position \`j\`:

\`\`\`
output[j] = ¬input[j]   (the same as 0xFF ⊕ input[j])
\`\`\`

NOT is its own inverse — applying it twice returns the original value.

## Where it fits

- **Bitwise Boolean formulas** — ciphers and hashes that express a step as
  AND/OR/NOT logic use NOT to negate an input. SHA-256's
  \`Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)\` selects between \`y\` and \`z\` based
  on \`x\`, and the \`¬x\` is this step.
- Any time a cipher needs the complement of a value rather than a fixed mask.`,
  params: new Map(),
  references: ["FIPS 180-4 §4.1.2 (SHA-256 helper function Ch)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
